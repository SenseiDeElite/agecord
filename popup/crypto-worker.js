/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// crypto-worker.js — Dedicated Web Worker for all passphrase-derived crypto

'use strict';

import { init, argon2id, xchacha20poly1305_encrypt, xchacha20poly1305_decrypt }
  from '../lib/rustcrypto-wasm.min.js';

// WASM init fires immediately but isn't awaited at top level — if we did,
// the module would finish evaluating after the first postMessage arrives,
// silently dropping it. Every handler awaits this promise instead.
const initReady = init();

//
// IMPORTANT — two incompatible envelope formats share version byte 0x01:
//   This worker (identity blobs): [ 0x01 ][ 16-byte Argon2id salt ][ nonce+ct+tag ]
//     Salt is embedded so blobs are portable / decryptable with passphrase alone.
//   background.js (contacts ciphertext): [ 0x01 ][ nonce+ct+tag ]
//     Salt lives separately in chrome.storage.local as "contactsSaltB64".
//   Do NOT unify these formats.
//

// ─── Constants ────────────────────────────────────────────────────────────────

// Argon2id: RFC 9106 §4 second recommended option (memory-constrained).
// m=64 MiB, t=3, p=1, output=32 bytes

const ENVELOPE_VERSION = 0x01;
const SALT_LEN         = 16;
const ARGON2_M_COST    = 65536;
const ARGON2_T_COST    = 3;
const ARGON2_P_COST    = 1;
const ARGON2_OUT_LEN   = 32;

// ─── Message handler ──────────────────────────────────────────────────────────

self.onmessage = async ({ data }) => {
  try {
    await initReady;
    // ── Argon2id key derivation ─────────────────────────────────────────────

    // Inputs are transferred ArrayBuffers. Outputs are transferred back; the
    // caller base64-encodes only before writing to chrome.storage

    if (data.op === 'ARGON2ID_DERIVE') {
      const passwordBytes = new Uint8Array(data.passwordBytes);
      const saltBytes     = new Uint8Array(data.saltBytes);
      let derived, out;
      try {
        derived = argon2id(passwordBytes, saltBytes, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, ARGON2_OUT_LEN);
        // Copy into a tightly-sized buffer before transferring — argon2id's
        // return value isn't guaranteed to own an exactly-sized buffer, and
        // transferring .buffer directly could leak whatever surrounds it.
        out = derived.slice();
        self.postMessage({ ok: true, keyBytes: out.buffer }, [out.buffer]);
      } finally {
        passwordBytes.fill(0);
        saltBytes.fill(0);
        derived?.fill(0);
        // `out` was just transferred and is now detached in this realm —
        // filling it would throw, and there's nothing left to zero anyway.
      }
      return;
    }

    if (data.op === 'XCHACHA_ENCRYPT') {
      const key       = new Uint8Array(data.keyBytes);
      const plaintext = new Uint8Array(data.plaintextBytes);
      if (!data.saltBytes) throw new Error('XCHACHA_ENCRYPT requires saltBytes — caller must supply it.');
      const saltRaw = new Uint8Array(data.saltBytes);
      if (saltRaw.length !== SALT_LEN)
        throw new Error(`Salt must be exactly ${SALT_LEN} bytes (got ${saltRaw.length}).`);

      // encrypt() generates the nonce internally via OsRng; returns nonce(24)||ct+tag.
      let noncePlusCt;
      try {
        noncePlusCt = xchacha20poly1305_encrypt(key, plaintext);
      } finally {
        key.fill(0);
        plaintext.fill(0);
      }

      // Freshly allocated to exact size, so transferring its buffer is safe.
      const envelope = new Uint8Array(1 + SALT_LEN + noncePlusCt.length);
      envelope[0] = ENVELOPE_VERSION;
      envelope.set(saltRaw, 1);
      envelope.set(noncePlusCt, 1 + SALT_LEN);
      noncePlusCt.fill(0);
      saltRaw.fill(0);

      self.postMessage({ ok: true, envelopeBytes: envelope.buffer }, [envelope.buffer]);
      return;
    }

    if (data.op === 'XCHACHA_DECRYPT') {
      const envelope = new Uint8Array(data.envelopeBytes);
      if (envelope[0] !== ENVELOPE_VERSION)
        throw new Error(`Unknown envelope version 0x${envelope[0].toString(16)}.`);

      const key = new Uint8Array(data.keyBytes);
      // decrypt() expects nonce(24)||ct+tag and slices the nonce internally.
      const noncePlusCt = envelope.slice(1 + SALT_LEN);
      let plaintext, out;
      try {
        plaintext = xchacha20poly1305_decrypt(key, noncePlusCt);
        // Same tight-copy-before-transfer reasoning as ARGON2ID_DERIVE.
        out = plaintext.slice();
      } finally {
        key.fill(0);
        plaintext?.fill(0);
      }

      self.postMessage({ ok: true, plaintextBytes: out.buffer }, [out.buffer]);
      return;
    }

    self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });

  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
