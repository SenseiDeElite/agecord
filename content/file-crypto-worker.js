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

// Single pipeThrough chain: source -> DecompressionStream -> TextDecoderStream.
async function decompressToText(bytes) {
  const source = new ReadableStream({
    start(controller) { controller.enqueue(bytes); controller.close(); },
  });
  const textStream = source
    .pipeThrough(new DecompressionStream('deflate-raw'))
    .pipeThrough(new TextDecoderStream());
  let text = '';
  for await (const chunk of textStream) text += chunk;
  return text;
}

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

// Verifies ML-DSA-87 signature and age-decrypts.
// Returns { sigValid: false } on failure, { sigValid: true, plainBytes } on success.
// Throws NOT_UNLOCKED if no identity is cached.
async function verifyAndDecrypt({ fileBuffer, candidateKeysB64,
                                  prefixBuffer, sigByteLen, pubkeyHintLen, opName }) {
  if (!fileBuffer || !(fileBuffer instanceof ArrayBuffer))
    throw new Error(`${opName}: fileBuffer must be a transferred ArrayBuffer`);
  if (!Array.isArray(candidateKeysB64) || candidateKeysB64.length === 0)
    throw new Error(`${opName}: candidateKeysB64 must be a non-empty array`);
  if (typeof sigByteLen !== 'number' || sigByteLen < 1)
    throw new Error(`${opName}: sigByteLen must be a positive number`);
  if (typeof pubkeyHintLen !== 'number' || pubkeyHintLen < 1)
    throw new Error(`${opName}: pubkeyHintLen must be a positive number`);
  if (fileBuffer.byteLength < sigByteLen + pubkeyHintLen + 1)
    throw new Error(`${opName}: fileBuffer too short`);
  if (!_cachedDecrypter)
    throw new Error('NOT_UNLOCKED');

  const fileBytes = new Uint8Array(fileBuffer);
  const sigBytes  = fileBytes.subarray(0, sigByteLen);
  const hintBytes = fileBytes.subarray(sigByteLen, sigByteLen + pubkeyHintLen);
  const ageBytes  = fileBytes.subarray(sigByteLen + pubkeyHintLen);

  // Remove trailing delimiter before key matching.
  // Missing delimiter indicates an invalid hint length.
  const hintStr      = _textDecoder.decode(hintBytes);
  const senderKeyB64 = hintStr.slice(0, -1);

  // One hint per message → scan runs at most once per attachment.
  const matchedKeyB64 = candidateKeysB64.find(k => k === senderKeyB64);
  if (!matchedKeyB64) return { sigValid: false };

  // ── Build sigInput: prefixBytes || hintBytes || ageBytes ───────────────────
  const prefixBytes = prefixBuffer ? new Uint8Array(prefixBuffer) : new Uint8Array(0);
  const sigInput    = new Uint8Array(prefixBytes.length + hintBytes.length + ageBytes.length);
  sigInput.set(prefixBytes, 0);
  sigInput.set(hintBytes,   prefixBytes.length);
  sigInput.set(ageBytes,    prefixBytes.length + hintBytes.length);

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

  if (!sigValid) return { sigValid: false };

  // ── age-decrypt ─────────────────────────────────────────────────────────────
  
  // ageBytes is a live view into fileBuffer, which is fully owned inside the
  // Worker (transferred in, not neutered here). No copy needed.
  const plainBytes = await _cachedDecrypter.decrypt(ageBytes, 'uint8array');

  return { sigValid: true, plainBytes };
}

// Blob shim completes before this module's init/onmessage setup; buffer sends until WORKER_READY.

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
      _cachedDecrypter = null;
      // Match the decrypter's lifecycle: drop cached sender keys too, so a
      // long-lived worker doesn't accumulate every correspondent's pubkey
      // across lock/unlock cycles.
      _pubKeyCache.clear();
      return;
    }

    if (op === 'ENCRYPT') {
      const { buffer, recipients } = data;

      if (!buffer || !(buffer instanceof ArrayBuffer))
        throw new Error('ENCRYPT: buffer must be a transferred ArrayBuffer');
      if (!Array.isArray(recipients) || recipients.length === 0)
        throw new Error('ENCRYPT: no recipients provided');

      const enc = new Encrypter();
      for (const recipient of recipients) enc.addRecipient(recipient);
      
      const plainBytes = new Uint8Array(buffer);
      const encBytes   = await enc.encrypt(plainBytes);

      // Transfer result back — encBytes.buffer is a fresh ArrayBuffer.
      self.postMessage(
        { op: 'ENCRYPT_RESULT', id, buffer: encBytes.buffer },
        [encBytes.buffer]
      );
      return;
    }

    // Used by the outgoing text-message path so CompressionStream never runs on
    // the main thread (Firefox Xray Vision tripped on it there).
    if (op === 'COMPRESS_ENCRYPT') {
      const { text, recipients } = data;

      if (typeof text !== 'string')
        throw new Error('COMPRESS_ENCRYPT: text must be a string');
      if (!Array.isArray(recipients) || recipients.length === 0)
        throw new Error('COMPRESS_ENCRYPT: no recipients provided');

      const compressedBytes = await compress(text);

      const enc = new Encrypter();
      for (const recipient of recipients) enc.addRecipient(recipient);
      const encBytes = await enc.encrypt(compressedBytes);

      self.postMessage(
        { op: 'COMPRESS_ENCRYPT_RESULT', id, buffer: encBytes.buffer },
        [encBytes.buffer]
      );
      return;
    }

    // VERIFY_DECRYPT: verify + decrypt signed media; return raw bytes.
    if (op === 'VERIFY_DECRYPT') {
      const { fileBuffer, candidateKeysB64, prefixBuffer, sigByteLen, pubkeyHintLen } = data;
      const result = await verifyAndDecrypt({ fileBuffer, candidateKeysB64,
                                              prefixBuffer, sigByteLen, pubkeyHintLen, opName: op });
      if (!result.sigValid) {
        self.postMessage({ op: 'VERIFY_DECRYPT_RESULT', id, sigValid: false });
        return;
      }
      // Return raw bytes — no decompress, no UTF-8 decode for binary media.
      self.postMessage(
        { op: 'VERIFY_DECRYPT_RESULT', id, sigValid: true, buffer: result.plainBytes.buffer },
        [result.plainBytes.buffer]
      );
      return;
    }

    // VERIFY_DECRYPT_DECOMPRESS: verify + decrypt signed text; decompress + UTF-8 decode.
    if (op === 'VERIFY_DECRYPT_DECOMPRESS') {
      const { fileBuffer, candidateKeysB64, prefixBuffer, sigByteLen, pubkeyHintLen } = data;
      const result = await verifyAndDecrypt({ fileBuffer, candidateKeysB64,
                                              prefixBuffer, sigByteLen, pubkeyHintLen, opName: op });
      if (!result.sigValid) {
        self.postMessage({ op: 'VERIFY_DECRYPT_DECOMPRESS_RESULT', id, sigValid: false });
        return;
      }
      const plaintext = await decompressToText(result.plainBytes);
      result.plainBytes.fill(0);
      self.postMessage({ op: 'VERIFY_DECRYPT_DECOMPRESS_RESULT', id, sigValid: true, plaintext });
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

// Signal readiness after registering self.onmessage.
self.postMessage({ op: 'WORKER_READY' });
