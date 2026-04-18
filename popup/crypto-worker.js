// crypto-worker.js — Dedicated Web Worker for all passphrase-derived crypto
//
// Runs in a dedicated Worker so the popup UI thread stays responsive during
// long-running key derivation.  A fresh worker is spawned per call and
// terminated on completion — no persistent state is kept here.
//
// Message protocol
// ─────────────────
//   Age wire format (DM encryption/decryption — age scrypt):
//   { op: 'DECRYPT', encryptedB64, passphrase }
//       → { ok: true,  identity }
//       → { ok: false, error }
//
//   { op: 'ENCRYPT', identityBlob, passphrase }
//       → { ok: true,  encryptedB64 }
//       → { ok: false, error }
//
//   Identity / contacts KDF (Argon2id):
//   { op: 'ARGON2ID_DERIVE', password, saltB64 }
//       password: UTF-8 string passphrase
//       saltB64:  base64-encoded 16-byte salt
//       → { ok: true,  keyB64 }   keyB64 = base64-encoded 32-byte derived key
//       → { ok: false, error }
//
//   Envelope encryption (XChaCha20-Poly1305 + managed nonce):
//   { op: 'XCHACHA_ENCRYPT', keyB64, plaintextB64 }
//       → { ok: true,  envelopeB64 }   format: [1 version][16 salt][managed-nonce ct]
//       → { ok: false, error }
//
//   { op: 'XCHACHA_DECRYPT', keyB64, envelopeB64 }
//       → { ok: true,  plaintextB64 }
//       → { ok: false, error }
//
// Envelope format (version 0x01):
//   [ 1 byte  version = 0x01          ]
//   [ 16 bytes Argon2id salt          ]
//   [ managedNonce ciphertext         ]  (24-byte nonce + ct + 16-byte Poly1305 tag)
//
// Note: ARGON2ID_DERIVE / XCHACHA_ENCRYPT / XCHACHA_DECRYPT are low-level
// primitives.  The high-level keygen/import/unlock paths in popup.js combine
// them as:  derive key from passphrase+salt → encrypt/decrypt with that key.

'use strict';

// ─── Library init ────────────────────────────────────────────────────────────

let _initError   = null;
let _nobleHashes = null;
let _nobleCiphers = null;

try {
  importScripts('../lib/age.min.js');
} catch (e) {
  _initError = 'Worker init failed (age): ' + (e?.message ?? String(e));
}

if (!_initError) {
  try {
    importScripts('../lib/awasm-noble.min.js');
    // awasm-noble exposes a global; try common bundle export names.
    const _awasm = (typeof awasmNoble !== 'undefined') ? awasmNoble
                 : (typeof globalThis.awasmNoble !== 'undefined') ? globalThis.awasmNoble
                 : null;
    if (!_awasm?.argon2id) throw new Error('argon2id not found in awasm-noble bundle');
    if (!_awasm?.xchacha20poly1305) throw new Error('xchacha20poly1305 not found in awasm-noble bundle');
    _nobleHashes  = _awasm;
    _nobleCiphers = _awasm;
  } catch (e) {
    _initError = 'Worker init failed (awasm-noble): ' + (e?.message ?? String(e));
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64) {
  // Tolerate base64url (- and .) as well as standard base64.
  let std = b64.replace(/-/g, '+').replace(/\./g, '/').replace(/_/g, '/');
  while (std.length % 4) std += '=';
  const bin = atob(std);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Argon2id parameters — RFC 9106 §4 second recommended option (memory-constrained).
// t=3, m=65536 (64 MiB), p=1, dkLen=32
// RFC 9106 §4 specifies p=4, but noble-hashes/awasm-noble run single-threaded in JS;
// p>1 would just run lanes sequentially with no memory benefit, so p=1 is kept.
// t is raised from 2 to 3 to exactly match the RFC's iteration-count recommendation.
const ARGON2ID_PARAMS = { t: 3, m: 65536, p: 1, dkLen: 32 };

// Envelope version byte.
const ENVELOPE_VERSION = 0x01;
const SALT_LEN         = 16;

// ─── Message handler ──────────────────────────────────────────────────────────

self.onmessage = async ({ data }) => {
  if (_initError) {
    self.postMessage({ ok: false, error: _initError });
    return;
  }

  try {
    // ── Age wire-format ops (DM encryption) ────────────────────────────────

    if (data.op === 'DECRYPT') {
      const d = new age.Decrypter();
      d.addPassphrase(data.passphrase);
      // age wire format uses the "disc" alphabet: - → +  . → /
      const raw     = base64ToBytes(data.encryptedB64);
      const bytes   = await d.decrypt(raw, 'uint8array');
      const identity = new TextDecoder().decode(bytes);
      self.postMessage({ ok: true, identity });
      return;
    }

    if (data.op === 'ENCRYPT') {
      const enc = new age.Encrypter();
      enc.setPassphrase(data.passphrase);
      enc.setScryptWorkFactor(18); // N = 2^18
      const ct = await enc.encrypt(new TextEncoder().encode(data.identityBlob));
      self.postMessage({ ok: true, encryptedB64: bytesToBase64(ct) });
      return;
    }

    // ── Argon2id key derivation ─────────────────────────────────────────────

    if (data.op === 'ARGON2ID_DERIVE') {
      const passwordBytes = new TextEncoder().encode(data.password);
      const saltBytes     = base64ToBytes(data.saltB64);
      const derived = _nobleHashes.argon2id(passwordBytes, saltBytes, ARGON2ID_PARAMS);
      self.postMessage({ ok: true, keyB64: bytesToBase64(derived) });
      return;
    }

    // ── XChaCha20-Poly1305 envelope encryption ──────────────────────────────
    // Envelope format: [ 0x01 version ][ 16-byte Argon2id salt ][ 24-byte nonce ][ ct + 16-byte tag ]
    // Nonce is generated fresh per encryption and stored in the envelope.
    // The Argon2id salt is embedded so the full blob is self-contained.

    const NONCE_LEN = 24; // XChaCha20 nonce length

    if (data.op === 'XCHACHA_ENCRYPT') {
      const key       = base64ToBytes(data.keyB64);
      const plaintext = base64ToBytes(data.plaintextB64);
      const salt      = data.saltB64 ? base64ToBytes(data.saltB64)
                                     : crypto.getRandomValues(new Uint8Array(SALT_LEN));
      const nonce     = crypto.getRandomValues(new Uint8Array(NONCE_LEN));

      const ct = _nobleCiphers.xchacha20poly1305(key, nonce).encrypt(plaintext);

      // Envelope: version | salt | nonce | ct
      const envelope = new Uint8Array(1 + SALT_LEN + NONCE_LEN + ct.length);
      envelope[0] = ENVELOPE_VERSION;
      envelope.set(salt.slice(0, SALT_LEN), 1);
      envelope.set(nonce, 1 + SALT_LEN);
      envelope.set(ct, 1 + SALT_LEN + NONCE_LEN);

      self.postMessage({ ok: true, envelopeB64: bytesToBase64(envelope) });
      return;
    }

    if (data.op === 'XCHACHA_DECRYPT') {
      const envelope = base64ToBytes(data.envelopeB64);
      if (envelope[0] !== ENVELOPE_VERSION)
        throw new Error(`Unknown envelope version 0x${envelope[0].toString(16)}.`);

      const key   = base64ToBytes(data.keyB64);
      const nonce = envelope.slice(1 + SALT_LEN, 1 + SALT_LEN + NONCE_LEN);
      const ct    = envelope.slice(1 + SALT_LEN + NONCE_LEN);

      const plaintext = _nobleCiphers.xchacha20poly1305(key, nonce).decrypt(ct);

      self.postMessage({ ok: true, plaintextB64: bytesToBase64(plaintext) });
      return;
    }

    self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });

  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
