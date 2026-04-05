// scrypt-worker.js — Web Worker for scrypt-heavy operations
//
// Loads age.min.js (for unlock DECRYPT) and noble-hashes.min.js (for async scrypt).
// All operations that need user-facing passphrases use nobleHashes.scryptAsync so
// the worker event loop yields periodically instead of blocking for 4+ seconds.
//
// Message protocol
// ─────────────────
//   { op: 'DECRYPT', encryptedB64, passphrase }
//       Decrypt an age-scrypt-wrapped identity (unlock flow).
//       → { ok: true, identity }  |  { ok: false, error }
//
//   { op: 'EXPORT_ENCRYPT', identityBlob, passphrase }
//       Encrypt a raw identity blob with an export passphrase.
//       Uses scryptAsync + AES-GCM-256. Output prefixed with 'v1:'.
//       → { ok: true, encryptedB64 }  |  { ok: false, error }
//
//   { op: 'EXPORT_DECRYPT', encryptedB64, passphrase }
//       Decrypt a v1: export blob back to the raw identity.
//       → { ok: true, identity }  |  { ok: false, error }

'use strict';

try {
  importScripts('../lib/age.min.js');
  importScripts('../lib/noble-hashes.min.js');
} catch (e) {
  const msg = { ok: false, error: 'Worker init failed: ' + (e?.message ?? e) };
  self.onmessage = () => self.postMessage(msg);
  self.postMessage(msg);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── Export format helpers ────────────────────────────────────────────────────
// Format: "v1:" + base64(salt_16) + "." + base64(iv_12) + "." + base64(ciphertext)
// KDF   : scryptAsync(passphrase, salt, N=2^18, r=8, p=1) → 32-byte AES key
// Cipher: AES-GCM-256

const SCRYPT_PARAMS = { N: 2 ** 18, r: 8, p: 1, dkLen: 32 };
const EXPORT_PREFIX = 'v1:';

async function exportEncrypt(identityBlob, passphrase) {
  const salt      = crypto.getRandomValues(new Uint8Array(16));
  const iv        = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(identityBlob);

  // scryptAsync yields every asyncTick ms — the worker event loop stays alive.
  const keyBytes = await nobleHashes.scryptAsync(passphrase, salt, SCRYPT_PARAMS);

  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);

  return EXPORT_PREFIX
    + bytesToBase64(salt) + '.'
    + bytesToBase64(iv)   + '.'
    + bytesToBase64(new Uint8Array(ct));
}

async function exportDecrypt(encoded, passphrase) {
  if (!encoded.startsWith(EXPORT_PREFIX)) throw new Error('Not a v1 export blob');
  const parts = encoded.slice(EXPORT_PREFIX.length).split('.');
  if (parts.length !== 3) throw new Error('Malformed export blob');
  const [salt, iv, ct] = parts.map(base64ToBytes);

  const keyBytes = await nobleHashes.scryptAsync(passphrase, salt, SCRYPT_PARAMS);

  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new TextDecoder().decode(plain);
}

// ─── Message handler ──────────────────────────────────────────────────────────

self.onmessage = async ({ data }) => {
  try {
    if (data.op === 'DECRYPT') {
      // Unlock path: age-scrypt-encrypted identity blob.
      const d = new age.Decrypter();
      d.addPassphrase(data.passphrase);
      const bytes    = await d.decrypt(base64ToBytes(data.encryptedB64), 'uint8array');
      const identity = new TextDecoder().decode(bytes);
      self.postMessage({ ok: true, identity });

    } else if (data.op === 'EXPORT_ENCRYPT') {
      const encryptedB64 = await exportEncrypt(data.identityBlob, data.passphrase);
      self.postMessage({ ok: true, encryptedB64 });

    } else if (data.op === 'EXPORT_DECRYPT') {
      const identity = await exportDecrypt(data.encryptedB64, data.passphrase);
      self.postMessage({ ok: true, identity });

    } else {
      self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });
    }
  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
