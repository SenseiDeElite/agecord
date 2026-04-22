// background.js — Discord Age Encryption service worker
//
// Key material flow:
//   popup      → UNLOCK           → background : identity blob + raw contacts key bytes
//   background → UNLOCK           → content    : signingKeyB64 (PKCS8 base64url)
//   content    → DECRYPT_MSG      → background : ciphertext → plaintext
//   popup      → ENCRYPT_CONTACTS → background : contacts JSON → ciphertextB64
//   popup      → DECRYPT_CONTACTS → background : ciphertextB64 → contacts JSON
//
// Contacts are encrypted at rest with XChaCha20-Poly1305.  The key is derived
// in the popup via Argon2id (noble-hashes) in crypto-worker.js and sent to the
// background as raw bytes in the UNLOCK message.  The background holds it as a
// plain Uint8Array (_contactsKeyBytes) — noble-ciphers does not use CryptoKey.
// The key is cleared on lock/restart.
//
// CryptoKey objects silently become {} when sent via chrome.tabs.sendMessage
// (Chrome JSON IPC drops them).  We send raw base64url PKCS8 bytes instead;
// the content script imports them into a non-extractable CryptoKey locally.

import { xchacha20poly1305 } from './lib/awasm-noble.min.js';
import { Decrypter } from './lib/age.min.js';

let _identity          = null;
let _contactsKeyBytes  = null; // raw Uint8Array from Argon2id derivation in popup
let _contacts          = {};   // latest decrypted contacts object, relayed to content scripts
let _ageRecipient      = null; // own public key string, relayed to content scripts

// noble-ciphers: xchacha20poly1305 used directly with an explicit nonce.
// We do NOT use managedNonce to avoid depending on it being present in the bundle.
// Contacts envelope format: [ 0x01 version ][ 24-byte nonce ][ ct + 16-byte tag ]
// (No salt — the Argon2id key is derived by the popup and sent in UNLOCK.)
function _xchacha_encrypt(key, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const ct    = xchacha20poly1305(key, nonce).encrypt(plaintext);
  // Prepend nonce to ciphertext so decrypt can recover it
  const out = new Uint8Array(24 + ct.length);
  out.set(nonce, 0);
  out.set(ct, 24);
  return out;
}

function _xchacha_decrypt(key, noncePlusCt) {
  const nonce = noncePlusCt.slice(0, 24);
  const ct    = noncePlusCt.slice(24);
  return xchacha20poly1305(key, nonce).decrypt(ct);
}

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

// ─── Contacts b64 helpers ────────────────────────────────────────────────────

// Base64url alphabet (RFC 4648 §5: + → -  / → _) — used for the contacts key
// (contactsKeyB64) which is sent from the popup as a base64url-encoded string.
function b64urlToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
}

// ─── Contacts encryption (XChaCha20-Poly1305) ────────────────────────────────
// Envelope format (version 0x01):
//   [ 1 byte version = 0x01 ][ 24-byte nonce ][ ct + 16-byte Poly1305 tag ]
//
// The Argon2id key is derived by the popup (crypto-worker.js) and sent here as
// raw bytes in the UNLOCK message.  The key is independent of the envelope —
// there is no salt embedded here.  If the key ever changes (passphrase change,
// fresh salt), saveContacts() re-encrypts with the new key and the old
// ciphertext is replaced atomically.

const ENVELOPE_VER      = 0x01;
const ENVELOPE_NONCE_LEN = 24;
const ENVELOPE_HDR_LEN  = 1; // just the version byte

function encryptContacts(jsonStr) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const plaintext   = new TextEncoder().encode(jsonStr);
  const noncePlusCt = _xchacha_encrypt(_contactsKeyBytes, plaintext); // 24-byte nonce + ct

  const envelope = new Uint8Array(ENVELOPE_HDR_LEN + noncePlusCt.length);
  envelope[0] = ENVELOPE_VER;
  envelope.set(noncePlusCt, ENVELOPE_HDR_LEN);
  return bytesToB64(envelope);
}

function decryptContacts(b64) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const envelope = b64ToBytes(b64);
  if (envelope[0] !== ENVELOPE_VER)
    throw new Error(`Unknown contacts envelope version 0x${envelope[0].toString(16)}.`);

  // Minimum viable length: version(1) + nonce(24) + tag(16) = 41 bytes.
  if (envelope.length < 41)
    throw new Error('Contacts envelope too short — data may be corrupt.');

  const noncePlusCt = envelope.slice(ENVELOPE_HDR_LEN);
  const plaintext   = _xchacha_decrypt(_contactsKeyBytes, noncePlusCt);
  return new TextDecoder().decode(plaintext);
}

// ─── Identity state ───────────────────────────────────────────────────────────
// Reconstructed from session storage if the service worker is killed and
// restarted mid-session.  _contactsKeyBytes cannot be reconstructed this way —
// the popup must re-send UNLOCK (with the Argon2id-derived contactsKeyB64) to
// restore it.

async function ensureIdentity() {
  if (_identity) return true;
  try {
    const d = await chrome.storage.session.get(['age_unlocked', 'age_identity', 'age_contacts', 'age_recipient']);
    if (!d.age_unlocked || !d.age_identity) return false;
    _identity = d.age_identity;
    // Restore contacts and recipient so sendUnlockToTab does not broadcast an
    // empty contacts object after a service-worker restart.  Without this,
    // every Discord tab would receive UNLOCK with contacts:{} and show
    // "No entry configured" until the popup is manually reopened.
    if (d.age_contacts && typeof d.age_contacts === 'object')
      _contacts = d.age_contacts;
    if (d.age_recipient)
      _ageRecipient = d.age_recipient;
    return true;
  } catch { return false; }
}

async function decryptPayload(cipherDisc) {
  const dec = new Decrypter();
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

        // Receive pre-derived Argon2id key bytes from popup's crypto-worker.
        // The key is passed as a base64 string and stored as a Uint8Array.
        if (msg.contactsKeyB64) {
          _contactsKeyBytes = b64ToBytes(msg.contactsKeyB64);
        }
      } catch (e) { console.info('[age] UNLOCK error:', e?.message); }
      sendResponse({ ok: true });
    })();
    return true;
  }


  if (msg.type === 'PING') {
    sendResponse({ ok: true, hasContactsKey: _contactsKeyBytes !== null });
    return false;
  }

  if (msg.type === 'RELOCK') {
    _identity         = null;
    _contactsKeyBytes = null;
    _contacts         = {};
    _ageRecipient     = null;
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
    try {
      sendResponse({ ok: true, ciphertextB64: encryptContacts(msg.json) });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
    return false;
  }

  if (msg.type === 'DECRYPT_CONTACTS') {
    try {
      sendResponse({ ok: true, json: decryptContacts(msg.ciphertextB64) });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
    return false;
  }
});
