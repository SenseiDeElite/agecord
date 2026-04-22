// crypto-worker.js — Dedicated Web Worker for all passphrase-derived crypto
import { argon2id, xchacha20poly1305 } from '../lib/awasm-noble.min.js';
import { Encrypter, Decrypter } from '../lib/age.min.js';
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

// ─── Library init ────────────────────────────────────────────────────────────
// ESM imports at top of file supply argon2id, xchacha20poly1305 (awasm-noble)
// and Encrypter, Decrypter (age-encryption).  No globals needed.

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// Standard base64 (btoa/atob alphabet — used for internal envelopes and salts).
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Base64url alphabet (RFC 4648 §5: + → -  / → _) — used for Ed25519 key material.
function b64urlToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
}

// "Disc" alphabet (+ → -  / → .) — used for age wire-format fields on Discord.
// Underscore is intentionally absent so Discord underline markup (__) is never triggered.
function b64discToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
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
  try {
    // ── Age wire-format ops (DM encryption) ────────────────────────────────

    if (data.op === 'DECRYPT') {
      const d = new Decrypter();
      d.addPassphrase(data.passphrase);
      // age wire format uses the "disc" alphabet: - → +  . → /
      const raw     = b64discToBytes(data.encryptedB64);
      const bytes   = await d.decrypt(raw, 'uint8array');
      const identity = new TextDecoder().decode(bytes);
      self.postMessage({ ok: true, identity });
      return;
    }

    if (data.op === 'ENCRYPT') {
      const enc = new Encrypter();
      enc.setPassphrase(data.passphrase);
      enc.setScryptWorkFactor(18); // N = 2^18
      const ct = await enc.encrypt(new TextEncoder().encode(data.identityBlob));
      self.postMessage({ ok: true, encryptedB64: bytesToBase64(ct) });
      return;
    }

    // ── Argon2id key derivation ─────────────────────────────────────────────

    if (data.op === 'ARGON2ID_DERIVE') {
      const passwordBytes = new TextEncoder().encode(data.password);
      const saltBytes     = b64ToBytes(data.saltB64);
      const derived = argon2id(passwordBytes, saltBytes, ARGON2ID_PARAMS);
      self.postMessage({ ok: true, keyB64: bytesToBase64(derived) });
      return;
    }

    // ── XChaCha20-Poly1305 envelope encryption ──────────────────────────────
    // Envelope format: [ 0x01 version ][ 16-byte Argon2id salt ][ 24-byte nonce ][ ct + 16-byte tag ]
    // Nonce is generated fresh per encryption and stored in the envelope.
    // The Argon2id salt is embedded so the full blob is self-contained.

    const NONCE_LEN = 24; // XChaCha20 nonce length

    if (data.op === 'XCHACHA_ENCRYPT') {
      const key       = b64ToBytes(data.keyB64);
      const plaintext = b64ToBytes(data.plaintextB64);
      const salt      = data.saltB64 ? b64ToBytes(data.saltB64)
                                     : crypto.getRandomValues(new Uint8Array(SALT_LEN));
      const nonce     = crypto.getRandomValues(new Uint8Array(NONCE_LEN));

      const ct = xchacha20poly1305(key, nonce).encrypt(plaintext);

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
      const envelope = b64ToBytes(data.envelopeB64);
      if (envelope[0] !== ENVELOPE_VERSION)
        throw new Error(`Unknown envelope version 0x${envelope[0].toString(16)}.`);

      const key   = b64ToBytes(data.keyB64);
      const nonce = envelope.slice(1 + SALT_LEN, 1 + SALT_LEN + NONCE_LEN);
      const ct    = envelope.slice(1 + SALT_LEN + NONCE_LEN);

      const plaintext = xchacha20poly1305(key, nonce).decrypt(ct);

      self.postMessage({ ok: true, plaintextB64: bytesToBase64(plaintext) });
      return;
    }

    self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });

  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
