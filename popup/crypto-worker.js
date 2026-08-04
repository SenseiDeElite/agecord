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

// IMPORTANT: Version 0x01 is shared by two incompatible envelope formats.

// Identity blobs (this worker):
//   [0x01][16-byte Argon2id salt][nonce+ct+tag]
//   Salt is embedded for passphrase-only recovery.

// Contacts ciphertext (background.js):
//   [0x01][nonce+ct+tag]
//   Salt is stored separately in chrome.storage.local.

// Keep formats separate; they are not interchangeable.

// ─── Constants ────────────────────────────────────────────────────────────────

// Argon2id: RFC 9106 §4 second recommended option (memory-constrained).
// m=64 MiB, t=3, p=1, output=32 bytes

const ENVELOPE_VERSION = 0x01;
const SALT_LEN         = 16;
const ARGON2_M_COST    = 65536;
const ARGON2_T_COST    = 3;
const ARGON2_P_COST    = 1;
const ARGON2_OUT_LEN   = 32;

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Zeros every provided buffer, skipping any that are null/undefined (e.g. an
// output that was never assigned because an earlier call threw). Centralizes
// the fill(0)-in-finally pattern repeated across every op below.
function zeroAll(...arrays) {
  for (const arr of arrays) arr?.fill(0);
}

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
        // `out` was just transferred and is now detached in this realm —
        // filling it would throw, and there's nothing left to zero anyway.
        zeroAll(passwordBytes, saltBytes, derived);
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
        zeroAll(key, plaintext);
      }

      // Freshly allocated to exact size, so transferring its buffer is safe.
      const envelope = new Uint8Array(1 + SALT_LEN + noncePlusCt.length);
      envelope[0] = ENVELOPE_VERSION;
      envelope.set(saltRaw, 1);
      envelope.set(noncePlusCt, 1 + SALT_LEN);
      zeroAll(noncePlusCt, saltRaw);

      self.postMessage({ ok: true, envelopeBytes: envelope.buffer }, [envelope.buffer]);
      return;
    }

    if (data.op === 'XCHACHA_DECRYPT') {
      const envelope = new Uint8Array(data.envelopeBytes);
      // Guard against truncated input before indexing — otherwise envelope[0]
      // is undefined and the check below throws an opaque TypeError instead
      // of this clear, intended error.
      if (envelope.length < 1 + SALT_LEN)
        throw new Error(`Envelope too short: expected at least ${1 + SALT_LEN} bytes, got ${envelope.length}.`);
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
        zeroAll(key, plaintext);
      }

      self.postMessage({ ok: true, plaintextBytes: out.buffer }, [out.buffer]);
      return;
    }

    self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });

  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
