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

// ─── Base64 helpers ───────────────────────────────────────────────────────────
const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

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

    if (data.op === 'ARGON2ID_DERIVE') {
      const passwordBytes = new TextEncoder().encode(data.password);
      const saltBytes     = fromB64(data.saltB64);
      const derived = argon2id(passwordBytes, saltBytes, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, ARGON2_OUT_LEN);
      self.postMessage({ ok: true, keyB64: toB64(derived) });
      return;
    }

    if (data.op === 'XCHACHA_ENCRYPT') {
      const key       = fromB64(data.keyB64);
      const plaintext = fromB64(data.plaintextB64);
      if (!data.saltB64) throw new Error('XCHACHA_ENCRYPT requires saltB64 — caller must supply it.');
      const saltRaw = fromB64(data.saltB64);
      if (saltRaw.length !== SALT_LEN)
        throw new Error(`Salt must be exactly ${SALT_LEN} bytes (got ${saltRaw.length}).`);

      // encrypt() generates the nonce internally via OsRng; returns nonce(24)||ct+tag.
      const noncePlusCt = xchacha20poly1305_encrypt(key, plaintext);

      const envelope = new Uint8Array(1 + SALT_LEN + noncePlusCt.length);
      envelope[0] = ENVELOPE_VERSION;
      envelope.set(saltRaw, 1);
      envelope.set(noncePlusCt, 1 + SALT_LEN);

      self.postMessage({ ok: true, envelopeB64: toB64(envelope) });
      return;
    }

    if (data.op === 'XCHACHA_DECRYPT') {
      const envelope = fromB64(data.envelopeB64);
      if (envelope[0] !== ENVELOPE_VERSION)
        throw new Error(`Unknown envelope version 0x${envelope[0].toString(16)}.`);

      const key = fromB64(data.keyB64);
      // decrypt() expects nonce(24)||ct+tag and slices the nonce internally.
      const noncePlusCt = envelope.slice(1 + SALT_LEN);
      const plaintext   = xchacha20poly1305_decrypt(key, noncePlusCt);

      self.postMessage({ ok: true, plaintextB64: toB64(plaintext) });
      return;
    }

    self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });

  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
