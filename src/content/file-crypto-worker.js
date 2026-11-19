/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// file-crypto-worker.js — Worker for file/text crypto: age encrypt/decrypt,
// compression, and ML-DSA-87 signing and verification.

// Format:
// [version 1 B][signature sigLen B][hint hintLen B][age ciphertext]

// Hint: UTF-8(base64(pubkey) + ":"); identifies the verification key.
// Signature covers prefix || hint || ciphertext; prefix is "<serverId>:<channelId>:"
// or "<channelId>:" and is rebuilt by the verifier, not stored.

// Encryption is fused: age-encrypt then sign in place, so unsigned ciphertext is never returned.
// ML-DSA seed arrives on UNLOCK and is zeroed on RELOCK.

'use strict';

const { age: ageUrl, sign: signUrl } = self.__AGE_LIB_URLS;
const { Encrypter, Decrypter } = await import(ageUrl);
const { init, ml_dsa87_sign, ml_dsa87_verify, ml_dsa87_verifying_key_from_seed } =
  await import(signUrl);

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

// Bumped on RELOCK so in-flight verifyAndDecrypt() / encrypt calls can detect stale work.
// Deliberately NOT bumped on UNLOCK (a harmless re-unlock must not fail in-flight decrypts).
let _lockEpoch = 0;

// ML-DSA-87 signing seed (32 bytes, secret). Set on UNLOCK, zeroed on RELOCK/replacement.
let _signSeed = null;
// Sender public key (base64) already proven to derive from _signSeed.
// Cleared on UNLOCK and RELOCK so the consistency check re-runs for a new seed.
let _signKeyVerifiedB64 = null;

// Validates the signed-file layout parameters shared by verify and sign.
// Returns where the hint starts and the total header length in front of the ciphertext.
function sigLayout({ fileOffset, sigByteLen, pubkeyHintLen }, opName) {
  if (typeof sigByteLen !== 'number' || sigByteLen < 1)
    throw new Error(`${opName}: sigByteLen must be a positive number`);
  if (typeof pubkeyHintLen !== 'number' || pubkeyHintLen < 1)
    throw new Error(`${opName}: pubkeyHintLen must be a positive number`);
  if (!Number.isInteger(fileOffset) || fileOffset < 0 || fileOffset > 16)
    throw new Error(`${opName}: fileOffset invalid`);
  return {
    hintStart: fileOffset + sigByteLen,
    headerLen: fileOffset + sigByteLen + pubkeyHintLen,
  };
}

// Writes the prefix directly in front of the hint, inside the signature field
// region (zero-copy), so prefix || hint || ciphertext is contiguous.
// Returns the prefix start offset.
function stagePrefix(fileBytes, hintStart, prefixBytes, sigByteLen, opName) {
  if (prefixBytes.length > sigByteLen) throw new Error(`${opName}: prefix too long`);
  const prefixStart = hintStart - prefixBytes.length;
  fileBytes.set(prefixBytes, prefixStart);
  return prefixStart;
}

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
  const { hintStart, headerLen: fileHeaderLen } = sigLayout({ fileOffset, sigByteLen, pubkeyHintLen }, opName);
  if (fileBuffer.byteLength < fileHeaderLen + 1)
    throw new Error(`${opName}: fileBuffer too short`);
  if (!_cachedDecrypter)
    throw new Error('NOT_UNLOCKED');
  const myEpoch = _lockEpoch;

  const fileBytes = new Uint8Array(fileBuffer);
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
  const sigBytes    = fileBytes.slice(fileOffset, fileOffset + sigByteLen);
  const prefixStart = stagePrefix(fileBytes, hintStart, prefixBytes, sigByteLen, opName);
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
    // Cache updates are synchronous, so queued VERIFY_DECRYPT[_DECOMPRESS] messages see them
    // before the handler yields. Validate first, then commit to avoid a half-unlocked state.
    // Adopt the received seed as-is; content.js transfers a private 32-byte copy.
    if (op === 'UNLOCK') {
      const { identityLine, mldsaSeed } = data;
      let dec;
      try {
        if (!identityLine || typeof identityLine !== 'string')
          throw new Error('UNLOCK: identityLine must be a string');
        if (!(mldsaSeed instanceof Uint8Array) || mldsaSeed.length !== 32 ||
            mldsaSeed.byteOffset !== 0 || mldsaSeed.buffer.byteLength !== 32)
          throw new Error('UNLOCK: mldsaSeed must be an exclusive 32-byte Uint8Array');
        dec = new Decrypter();
        dec.addIdentity(identityLine);
      } catch (e) {
        if (mldsaSeed instanceof Uint8Array) mldsaSeed.fill(0);
        throw e;
      }
      _signSeed?.fill(0);
      _signSeed = mldsaSeed;
      _signKeyVerifiedB64 = null;
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
      _signSeed?.fill(0);
      _signSeed = null;
      _signKeyVerifiedB64 = null;
      return;
    }

    // Fused encrypt + sign. ENCRYPT takes a transferred buffer; COMPRESS_ENCRYPT
    // (outgoing text, so CompressionStream never runs on the main thread - Firefox
    // Xray Vision) takes a string. Returns the COMPLETE signed file
    // [version][signature][hint][age ciphertext]; there is no unsigned output path.
    if (op === 'ENCRYPT' || op === 'COMPRESS_ENCRYPT') {
      let plainBytes = null;
      let encBytes;
      let sign, fileHeaderLen, hintStart, myEpoch;
      try {
        // Obtain the plaintext holder first so the finally zeroes it on EVERY exit.
        if (op === 'ENCRYPT') {
          if (!(data.buffer instanceof ArrayBuffer))
            throw new Error('ENCRYPT: buffer must be a transferred ArrayBuffer');
          plainBytes = new Uint8Array(data.buffer);
        } else {
          if (typeof data.text !== 'string')
            throw new Error('COMPRESS_ENCRYPT: text must be a string');
          plainBytes = await compress(data.text);
        }

        const { recipients } = data;
        if (!Array.isArray(recipients) || recipients.length === 0)
          throw new Error(`${op}: no recipients provided`);

        // `sign` is mandatory. Re-validate every field; never trust the sender.
        sign = data.sign;
        if (!sign || typeof sign !== 'object')
          throw new Error(`${op}: sign context required`);
        if (!(sign.prefixBuffer instanceof ArrayBuffer))
          throw new Error(`${op}: sign.prefixBuffer must be an ArrayBuffer`);
        if (!Number.isInteger(sign.sigByteLen) || !Number.isInteger(sign.pubkeyHintLen))
          throw new Error(`${op}: sign layout lengths must be integers`);
        if (typeof sign.senderPubKeyB64 !== 'string' ||
            !/^[A-Za-z0-9+/]+=*$/.test(sign.senderPubKeyB64) ||
            sign.senderPubKeyB64.length + 1 !== sign.pubkeyHintLen)
          throw new Error(`${op}: bad senderPubKeyB64`);
        if (sign.fileOffset !== 1)
          throw new Error(`${op}: fileOffset must be 1`);
        if (!Number.isInteger(sign.version) || sign.version < 0 || sign.version > 255)
          throw new Error(`${op}: bad version`);
        ({ hintStart, headerLen: fileHeaderLen } = sigLayout(sign, op));
        if (sign.prefixBuffer.byteLength > sign.sigByteLen)
          throw new Error(`${op}: prefix too long`);

        // Fail fast; re-checked right before signing.
        if (!_signSeed) throw new Error('NOT_UNLOCKED');

        myEpoch = _lockEpoch;
        const enc = new Encrypter();
        for (const recipient of recipients) enc.addRecipient(recipient);
        encBytes = await enc.encrypt(plainBytes);
      } finally {
        if (plainBytes) plainBytes.fill(0);
      }

      // The one remaining full-size copy: [header][ciphertext] in a single buffer.
      // Ciphertext is public data and is not zeroed.
      const out = new Uint8Array(fileHeaderLen + encBytes.length);
      out.set(encBytes, fileHeaderLen);
      encBytes = null;

      // NO await from here to the sign call: nothing can relock or replace the seed in between.
      if (_lockEpoch !== myEpoch || !_signSeed) throw new Error('NOT_UNLOCKED');
      if (_signKeyVerifiedB64 !== sign.senderPubKeyB64) {
        const derived = ml_dsa87_verifying_key_from_seed(_signSeed);
        if (derived.toBase64() !== sign.senderPubKeyB64)
          throw new Error('SIGNING_KEY_MISMATCH');
        _signKeyVerifiedB64 = sign.senderPubKeyB64;
      }

      // Assemble in place: hint straight into the buffer, prefix staged in the
      // (still unused) signature field, then sign prefix || hint || ciphertext.
      const hintStr = sign.senderPubKeyB64 + ':';
      const { read, written } = new TextEncoder().encodeInto(
        hintStr, out.subarray(hintStart, hintStart + sign.pubkeyHintLen));
      if (read !== hintStr.length || written !== sign.pubkeyHintLen)
        throw new Error(`${op}: hint encoding failed`);
      const prefixStart = stagePrefix(out, hintStart, new Uint8Array(sign.prefixBuffer),
                                      sign.sigByteLen, op);
      const sig = ml_dsa87_sign(_signSeed, out.subarray(prefixStart));
      if (sig.length !== sign.sigByteLen)
        throw new Error(`${op}: unexpected signature length`);
      out[0] = sign.version;
      out.set(sig, sign.fileOffset); // overwrites the staged prefix

      self.postMessage({ op: `${op}_RESULT`, id, buffer: out.buffer }, [out.buffer]);
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
