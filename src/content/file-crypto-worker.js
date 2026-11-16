/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// file-crypto-worker.js — Worker for file encryption/decryption
//
// Format:
// [sigLen bytes sig][hintLen bytes hint][age ciphertext]
//
// Hint: UTF-8(base64(pubkey) + ":")
// Used to locate verification key; signature covers prefix + hint + ciphertext.

'use strict';

import { Encrypter, Decrypter }   from '../lib/age.min.js';
import { init, ml_dsa87_verify } from '../lib/rustcrypto-wasm.min.js';

await init();

// ─── Compression helpers ───────────────────────────────────────────────────────

// Uses pipeThrough()/pipeTo() to keep compression/decompression inside the
// Worker, avoiding Firefox Xray Vision on CompressionStream and keeping
// plaintext/decrypted data off the main thread.

// Drains a ReadableStream<Uint8Array> into a single Uint8Array.
async function collectBytes(readable) {
  const chunks = [];
  await readable.pipeTo(new WritableStream({
    write(chunk) { chunks.push(chunk); },
  }));
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// Single pipeThrough chain: source -> TextEncoderStream -> CompressionStream.
function compress(str) {
  const source = new ReadableStream({
    start(controller) { controller.enqueue(str); controller.close(); },
  });
  const compressed = source
    .pipeThrough(new TextEncoderStream())
    .pipeThrough(new CompressionStream('deflate-raw'));
  return collectBytes(compressed);
}

// Source -> DecompressionStream -> byte-counting limiter -> TextDecoderStream.
// The limiter errors once decompressed output exceeds maxBytes, preventing large strings;
// the cap may be exceeded by at most one decompressor chunk.
async function decompressToTextCapped(bytes, maxBytes) {
  let total = 0;
  const limiter = new TransformStream({
    transform(chunk, ctl) {
      total += chunk.byteLength;
      if (total > maxBytes) { ctl.error(new Error('TEXT_TOO_LARGE')); return; }
      ctl.enqueue(chunk);
    },
  });
  const source = new ReadableStream({
    start(controller) { controller.enqueue(bytes); controller.close(); },
  });
  const stream = source
    .pipeThrough(new DecompressionStream('deflate-raw'))
    .pipeThrough(limiter)
    .pipeThrough(new TextDecoderStream());
  let text = '';
  for await (const chunk of stream) text += chunk;
  return text;
}

// 4,000 UTF-16 units x 3 bytes (BMP worst case in UTF-8).
// KEEP IN SYNC (content.js MAX_INLINE_MESSAGE_CHARS * 3)
const TEXT_MAX_PLAINTEXT_BYTES = 4000 * 3;

// Decoded ML-DSA-87 public keys (2592 B each) keyed by base64 string.
// Avoids repeated base64 decode across attachments in the same channel.
const _pubKeyCache = new Map();
const _textDecoder = new TextDecoder();

function decodePubKey(b64) {
  let key = _pubKeyCache.get(b64);
  if (!key) { key = Uint8Array.fromBase64(b64); _pubKeyCache.set(b64, key); }
  return key;
}

// Cached decryption identity.
// Set on UNLOCK, cleared on RELOCK.
// Avoids resending on verify/decrypt paths.
let _cachedDecrypter = null;

// Bumped on RELOCK so in-flight verifyAndDecrypt() calls can detect stale work.
let _lockEpoch = 0;

// Verifies ML-DSA-87, then age-decrypts.
// Signature failures return sigValid=false with unknown-sender or bad-signature.
// Valid but unaddressed messages return not-recipient; success returns plainBytes.
// Throws NOT_UNLOCKED without a cached identity.
// fileOffset marks the signature start in fileBuffer (1 = after version), avoiding a slice(1) copy.
async function verifyAndDecrypt({ fileBuffer, candidateKeysB64,
                                  prefixBuffer, sigByteLen, pubkeyHintLen, fileOffset = 0, opName }) {
  if (!fileBuffer || !(fileBuffer instanceof ArrayBuffer))
    throw new Error(`${opName}: fileBuffer must be a transferred ArrayBuffer`);
  if (!Array.isArray(candidateKeysB64) || candidateKeysB64.length === 0)
    throw new Error(`${opName}: candidateKeysB64 must be a non-empty array`);
  if (typeof sigByteLen !== 'number' || sigByteLen < 1)
    throw new Error(`${opName}: sigByteLen must be a positive number`);
  if (typeof pubkeyHintLen !== 'number' || pubkeyHintLen < 1)
    throw new Error(`${opName}: pubkeyHintLen must be a positive number`);
  if (!Number.isInteger(fileOffset) || fileOffset < 0 || fileOffset > 16)
    throw new Error(`${opName}: fileOffset invalid`);
  if (fileBuffer.byteLength < fileOffset + sigByteLen + pubkeyHintLen + 1)
    throw new Error(`${opName}: fileBuffer too short`);
  if (!_cachedDecrypter)
    throw new Error('NOT_UNLOCKED');
  const myEpoch = _lockEpoch;

  const fileBytes = new Uint8Array(fileBuffer);
  const hintStart = fileOffset + sigByteLen;
  const hintBytes = fileBytes.subarray(hintStart, hintStart + pubkeyHintLen);
  const ageBytes  = fileBytes.subarray(hintStart + pubkeyHintLen);

  // Remove trailing delimiter before key matching.
  // Missing delimiter indicates an invalid hint length.
  const hintStr      = _textDecoder.decode(hintBytes);
  // The trailing delimiter must actually be ':' — slice(0, -1) alone would accept any last character.
  if (!hintStr.endsWith(':')) return { sigValid: false, reason: 'unknown-sender' };
  const senderKeyB64 = hintStr.slice(0, -1);

  // One hint per message → scan runs at most once per attachment.
  const matchedKeyB64 = candidateKeysB64.find(k => k === senderKeyB64);
  if (!matchedKeyB64) return { sigValid: false, reason: 'unknown-sender' };

  // Build prefix || hint || age in place.
  // Move the 4,627-byte signature aside first, then write the <=42-byte prefix into
  // its former region before hint; age bytes remain untouched and no large copy occurs.
  const prefixBytes = prefixBuffer ? new Uint8Array(prefixBuffer) : new Uint8Array(0);
  if (prefixBytes.length > sigByteLen) throw new Error(`${opName}: prefix too long`);
  const sigBytes    = fileBytes.slice(fileOffset, fileOffset + sigByteLen);
  const prefixStart = hintStart - prefixBytes.length;
  fileBytes.set(prefixBytes, prefixStart);
  const sigInput    = fileBytes.subarray(prefixStart);

  // ── Verify with the single matched key ─────────────────────────────────────
  
  // arg order: ml_dsa87_verify(verifying_key, message, signature)
  let sigValid = false;
  try {
    sigValid = ml_dsa87_verify(decodePubKey(matchedKeyB64), sigInput, sigBytes);
  } catch (e) {
    // Malformed key or sig — sigValid stays false, but log so a real
    // wasm-call bug (bad arg types, panic, etc.) isn't indistinguishable
    // from an ordinary failed verification.
    console.error(`[age] ${opName}: ml_dsa87_verify threw:`, e?.message ?? e);
  }

  if (!sigValid) return { sigValid: false, reason: 'bad-signature' };

  // ── age-decrypt ─────────────────────────────────────────────────────────────
  
  // ageBytes is a live view into fileBuffer, which is fully owned inside the
  // Worker (transferred in, not neutered here). No copy needed.

  // Signature is verified, so a no matching recipient failure means this message targets other recipients.
  // age exposes this as a plain Error; match its text only, falling back if wording changes.
  let plainBytes;
  try {
    plainBytes = await _cachedDecrypter.decrypt(ageBytes, 'uint8array');
  } catch (e) {
    if (/no identity matched/i.test(e?.message ?? '')) return { sigValid: true, reason: 'not-recipient' };
    throw e;
  }

  // Reject plaintext if RELOCK occurred during the in-flight decrypt.
  if (_lockEpoch !== myEpoch) {
    plainBytes.fill(0);
    throw new Error('NOT_UNLOCKED');
  }

  return { sigValid: true, plainBytes };
}

self.onmessage = async ({ data }) => {
  const { op, id } = data;

  try {
    // UNLOCK/RELOCK are fire-and-forget (no `id`).
    // Cache update is synchronous, so queued    VERIFY_DECRYPT[_DECOMPRESS]
    // messages observe it before this handler yields.
    if (op === 'UNLOCK') {
      const { identityLine } = data;
      if (!identityLine || typeof identityLine !== 'string')
        throw new Error('UNLOCK: identityLine must be a string');
      const dec = new Decrypter();
      dec.addIdentity(identityLine);
      _cachedDecrypter = dec;
      return;
    }

    if (op === 'RELOCK') {
      _lockEpoch++;
      _cachedDecrypter = null;
      // Match the decrypter's lifecycle: drop cached sender keys too, so a
      // long-lived worker doesn't accumulate every correspondent's pubkey
      // across lock/unlock cycles.
      _pubKeyCache.clear();
      return;
    }

    if (op === 'ENCRYPT' || op === 'COMPRESS_ENCRYPT') {
      const { recipients } = data;
      if (!Array.isArray(recipients) || recipients.length === 0)
        throw new Error(`${op}: no recipients provided`);
      // Bytes to leave free IN FRONT of the ciphertext (content.js signs in place and writes the signed-file header
      // there, so the main thread never copies the ciphertext). 0 = ciphertext at offset 0.
      const headerLen = data.headerLen ?? 0;
      if (!Number.isInteger(headerLen) || headerLen < 0 || headerLen > 65536)
        throw new Error(`${op}: bad headerLen`);

      // ENCRYPT takes a transferred buffer; COMPRESS_ENCRYPT (outgoing text, so
      // CompressionStream never runs on the main thread - Firefox Xray Vision)
      // takes a string. Either way the plaintext bytes are zeroed after use.
      let plainBytes;
      if (op === 'ENCRYPT') {
        if (!(data.buffer instanceof ArrayBuffer))
          throw new Error('ENCRYPT: buffer must be a transferred ArrayBuffer');
        plainBytes = new Uint8Array(data.buffer);
      } else {
        if (typeof data.text !== 'string')
          throw new Error('COMPRESS_ENCRYPT: text must be a string');
        plainBytes = await compress(data.text);
      }
      let encBytes;
      try {
        const enc = new Encrypter();
        for (const recipient of recipients) enc.addRecipient(recipient);
        encBytes = await enc.encrypt(plainBytes);
      } finally {
        plainBytes.fill(0);
      }
      // encBytes.buffer is a fresh ArrayBuffer; transfer it back (with headerLen free bytes in front, if asked).
      let outBytes = encBytes;
      if (headerLen > 0) { outBytes = new Uint8Array(headerLen + encBytes.length); outBytes.set(encBytes, headerLen); }
      self.postMessage({ op: `${op}_RESULT`, id, buffer: outBytes.buffer }, [outBytes.buffer]);
      return;
    }

    // VERIFY_DECRYPT: signed media, raw bytes back (no decompress / UTF-8 decode).
    // VERIFY_DECRYPT_DECOMPRESS: signed text, decompressed + UTF-8 decoded.
    if (op === 'VERIFY_DECRYPT' || op === 'VERIFY_DECRYPT_DECOMPRESS') {
      const { fileBuffer, candidateKeysB64, prefixBuffer, sigByteLen, pubkeyHintLen, fileOffset } = data;
      const result = await verifyAndDecrypt({ fileBuffer, candidateKeysB64,
                                              prefixBuffer, sigByteLen, pubkeyHintLen, fileOffset, opName: op });
      const resultOp = `${op}_RESULT`;
      if (!result.sigValid || result.reason === 'not-recipient') {
        self.postMessage({ op: resultOp, id, sigValid: result.sigValid, reason: result.reason });
        return;
      }
      if (op === 'VERIFY_DECRYPT') {
        self.postMessage({ op: resultOp, id, sigValid: true, buffer: result.plainBytes.buffer }, [result.plainBytes.buffer]);
        return;
      }
      let plaintext;
      try {
        plaintext = await decompressToTextCapped(result.plainBytes, TEXT_MAX_PLAINTEXT_BYTES);
      } finally {
        result.plainBytes.fill(0);
      }
      self.postMessage({ op: resultOp, id, sigValid: true, plaintext });
      return;
    }

    self.postMessage({ op: 'ERROR', id, error: `Unknown op: ${op}` });

  } catch (e) {
    const message = e?.message ?? String(e);
    if (id === undefined) {
      // UNLOCK/RELOCK carry no id, so content.js's pendingMap has nowhere to
      // route a posted error — log locally instead of failing silently.
      console.error(`[age] file-crypto-worker ${op} error:`, message);
      return;
    }
    self.postMessage({ op: `${op}_ERROR`, id, error: message });
  }
};

// Signal readiness after registering onmessage so buffered messages can flush.
self.postMessage({ op: 'WORKER_READY' });
