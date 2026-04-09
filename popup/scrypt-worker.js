// scrypt-worker.js — Dedicated Web Worker for scrypt-heavy passphrase operations
//
// Runs in a dedicated Worker so the popup UI thread stays responsive during the
// 2–10 s scrypt computation at N=2^18.  A fresh worker is spawned per call and
// terminated on completion — no persistent state is kept here.
//
// Message protocol
// ─────────────────
//   { op: 'DECRYPT', encryptedB64, passphrase }
//       Decrypt an age-scrypt-wrapped identity blob (unlock / passphrase-verify).
//       → { ok: true,  identity }
//       → { ok: false, error }
//
//   { op: 'ENCRYPT', identityBlob, passphrase }
//       Encrypt a raw identity blob with age scrypt (N=2^18).
//       Used by keygen and import flows.
//       → { ok: true,  encryptedB64 }
//       → { ok: false, error }

'use strict';

let _initError = null;
try {
  importScripts('../lib/age.min.js');
} catch (e) {
  _initError = 'Worker init failed: ' + (e?.message ?? String(e));
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── Message handler ──────────────────────────────────────────────────────────

self.onmessage = async ({ data }) => {
  if (_initError) {
    self.postMessage({ ok: false, error: _initError });
    return;
  }

  try {
    if (data.op === 'DECRYPT') {
      const d = new age.Decrypter();
      d.addPassphrase(data.passphrase);
      const bytes    = await d.decrypt(base64ToBytes(data.encryptedB64), 'uint8array');
      const identity = new TextDecoder().decode(bytes);
      self.postMessage({ ok: true, identity });

    } else if (data.op === 'ENCRYPT') {
      const enc = new age.Encrypter();
      enc.setPassphrase(data.passphrase);
      enc.setScryptWorkFactor(18); // N = 2^18
      const ct = await enc.encrypt(new TextEncoder().encode(data.identityBlob));
      self.postMessage({ ok: true, encryptedB64: bytesToBase64(ct) });

    } else {
      self.postMessage({ ok: false, error: 'Unknown op: ' + data.op });
    }
  } catch (e) {
    self.postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};
