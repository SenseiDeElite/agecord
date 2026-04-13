// background.js — Discord Age Encryption service worker
//
// Key material flow:
//   popup      → UNLOCK           → background : identity blob + passphrase
//   background → UNLOCK           → content    : signingKeyB64 (PKCS8 base64url)
//   content    → DECRYPT_MSG      → background : ciphertext → plaintext
//   popup      → ENCRYPT_CONTACTS → background : contacts JSON → ciphertextB64
//   popup      → DECRYPT_CONTACTS → background : ciphertextB64 → contacts JSON
//
// Contacts are encrypted at rest with AES-GCM-256.  The key is derived via
// PBKDF2 (SHA-256, 200 000 iterations) from the passphrase at unlock time,
// held in memory as a non-extractable CryptoKey, and cleared on lock/restart.
// A dedicated salt ("contactsSalt") is stored in chrome.storage.local —
// distinct from the age-scrypt identity salt — so the two blobs cannot
// cross-attack each other.
//
// CryptoKey objects silently become {} when sent via chrome.tabs.sendMessage
// (Chrome JSON IPC drops them).  We send raw base64url PKCS8 bytes instead;
// the content script imports them into a non-extractable CryptoKey locally.

'use strict';

importScripts('lib/age.min.js');

let _identity      = null;
let _contactsKey   = null;
let _contacts      = {};   // latest decrypted contacts object, relayed to content scripts
let _ageRecipient  = null; // own public key string, relayed to content scripts

// ─── Base64 helpers ───────────────────────────────────────────────────────────

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// "Disc" alphabet: + → -  / → .  (used in age wire format to avoid Discord markdown)
function discToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
}

function getSigningKeyB64(identityBlob) {
  const line = identityBlob.split('\n')[1] ?? '';
  if (!line.startsWith('ed25519priv:')) throw new Error('No Ed25519 private key in identity blob');
  return line.slice('ed25519priv:'.length);
}

async function decompress(bytes) {
  const stream = new DecompressionStream('deflate-raw');
  const writer = stream.writable.getWriter();
  writer.write(bytes);
  writer.close();
  const chunks = [];
  const reader = stream.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return new TextDecoder().decode(out);
}

// ─── Contacts key derivation and encryption ───────────────────────────────────
// PBKDF2 chosen over raw HKDF-on-scrypt because typage's scrypt output is
// opaque — we cannot extract raw bytes from it.  PBKDF2 at 200k iterations
// provides comparable protection for this secondary key derivation.

async function deriveContactsKey(passphraseBytes, saltBytes) {
  const km = await crypto.subtle.importKey('raw', passphraseBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 200_000 },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Wire format: 12-byte random IV prepended to AES-GCM ciphertext, base64-encoded.
async function encryptContacts(jsonStr) {
  if (!_contactsKey) throw new Error('Contacts key not available — extension locked.');
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _contactsKey,
    new TextEncoder().encode(jsonStr));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return bytesToB64(out);
}

async function decryptContacts(b64) {
  if (!_contactsKey) throw new Error('Contacts key not available — extension locked.');
  const raw = b64ToBytes(b64);
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) },
    _contactsKey, raw.slice(12));
  return new TextDecoder().decode(pt);
}

// ─── Identity state ───────────────────────────────────────────────────────────
// Reconstructed from session storage if the service worker is killed and
// restarted mid-session.  _contactsKey cannot be reconstructed this way —
// the popup must re-send UNLOCK with the passphrase to re-derive it.

async function ensureIdentity() {
  if (_identity) return true;
  try {
    const d = await chrome.storage.session.get(['age_unlocked', 'age_identity']);
    if (!d.age_unlocked || !d.age_identity) return false;
    _identity = d.age_identity;
    return true;
  } catch { return false; }
}

async function decryptPayload(cipherDisc) {
  const dec = new age.Decrypter();
  dec.addIdentity(_identity.split('\n')[0]);
  const compressed = await dec.decrypt(discToBytes(cipherDisc), 'uint8array');
  return decompress(compressed);
}

async function sendUnlockToTab(tabId) {
  if (!(await ensureIdentity())) return;
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'UNLOCK',
      signingKeyB64: getSigningKeyB64(_identity),
      contacts:      _contacts,
      ageRecipient:  _ageRecipient,
    });
  } catch {}
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url?.startsWith('https://discord.com/')) return;
  setTimeout(() => sendUnlockToTab(tabId), 800);
});

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {

  if (msg.type === 'UNLOCK') {
    (async () => {
      try {
        _identity     = msg.identity;
        _contacts     = msg.contacts     ?? _contacts;
        _ageRecipient = msg.ageRecipient ?? _ageRecipient;
        const tabs = await chrome.tabs.query({ url: 'https://discord.com/*' });
        for (const tab of tabs)
          chrome.tabs.sendMessage(tab.id, {
            type: 'UNLOCK',
            signingKeyB64: getSigningKeyB64(_identity),
            contacts:      _contacts,
            ageRecipient:  _ageRecipient,
          }, () => void chrome.runtime.lastError);

        if (msg.passphrase) {
          let saltB64 = (await chrome.storage.local.get('contactsSalt')).contactsSalt;
          if (!saltB64) {
            saltB64 = bytesToB64(crypto.getRandomValues(new Uint8Array(32)));
            await chrome.storage.local.set({ contactsSalt: saltB64 });
          }
          _contactsKey = await deriveContactsKey(
            new TextEncoder().encode(msg.passphrase), b64ToBytes(saltB64));
        }
      } catch (e) { console.info('[age] UNLOCK error:', e?.message); }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg.type === 'RELOCK') {
    _identity     = null;
    _contactsKey  = null;
    _contacts     = {};
    _ageRecipient = null;
    chrome.tabs.query({ url: 'https://discord.com/*' }, tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, { type: 'RELOCK' }, () => void chrome.runtime.lastError);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'RELOAD_DISCORD_TABS') {
    chrome.tabs.query({ url: 'https://discord.com/*' })
      .then(tabs => tabs.forEach(t => chrome.tabs.reload(t.id)))
      .catch(() => {});
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'CONTACTS_UPDATED') {
    if (msg.contacts)     _contacts     = msg.contacts;
    if (msg.ageRecipient) _ageRecipient = msg.ageRecipient;
    chrome.tabs.query({ url: 'https://discord.com/*' }, tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, {
          type: 'CONTACTS_UPDATED',
          contacts:     _contacts,
          ageRecipient: _ageRecipient,
        }, () => void chrome.runtime.lastError);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'DECRYPT_MSG') {
    (async () => {
      try {
        if (!(await ensureIdentity())) { sendResponse({ ok: false, error: 'locked' }); return; }
        sendResponse({ ok: true, plaintext: await decryptPayload(msg.cipher) });
      } catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }

  if (msg.type === 'ENCRYPT_CONTACTS') {
    (async () => {
      try { sendResponse({ ok: true, ciphertextB64: await encryptContacts(msg.json) }); }
      catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }

  if (msg.type === 'DECRYPT_CONTACTS') {
    (async () => {
      try { sendResponse({ ok: true, json: await decryptContacts(msg.ciphertextB64) }); }
      catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }
});
