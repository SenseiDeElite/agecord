// background.js — Discord Age Encryption service worker
//
// Key material flow:
//   popup → UNLOCK → background : identity blob + contacts key (b64)
//   background → UNLOCK → content : mldsaSeedB64 (ML-DSA-87 32-byte seed)
//   content → GET_IDENTITY_LINE → background : age X25519 identity line
//   popup → ENCRYPT_CONTACTS / DECRYPT_CONTACTS → background : contacts JSON ↔ ciphertextB64
//
// Per-message decryption is entirely in the content script (file-crypto-worker).
//
// chrome.storage.session is the correct location for transient unlock state —
// it is inaccessible to web pages and content scripts by the browser sandbox.

'use strict';

import { init as _rustcryptoInit, xchacha20poly1305_encrypt, xchacha20poly1305_decrypt }
  from './lib/rustcrypto-wasm.min.js';

// init() is idempotent. Fire it immediately so WASM is ready before any message
// arrives, but service workers forbid top-level await — store the Promise instead.
const _wasmReady = _rustcryptoInit();

let _identity          = null;
let _contactsKeyBytes  = null; // raw Uint8Array, derived by popup's crypto-worker
let _contacts          = {};
let _ageRecipient      = null;

// ─── Base64 helpers ───────────────────────────────────────────────────────────
const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

// ─── XChaCha20-Poly1305 helpers ───────────────────────────────────────────────
// Contacts envelope format: [ 0x01 version ][ 24-byte nonce ][ ct + 16-byte tag ]
// Stored as standard base64 in chrome.storage.local under key "contactsEnc".
//
// NOTE: crypto-worker.js uses a structurally incompatible envelope that embeds
// the Argon2id salt: [ 0x01 ][ 16-byte salt ][ 24-byte nonce ][ ct+tag ].
// Here the salt lives separately in chrome.storage.local ("contactsSaltB64").
// Do not unify these formats — the duplication is deliberate.

function _xchacha_encrypt(key, plaintext) {
  return xchacha20poly1305_encrypt(key, plaintext);
}

function _xchacha_decrypt(key, noncePlusCt) {
  return xchacha20poly1305_decrypt(key, noncePlusCt);
}

// Identity blob: line 0 = AGE-SECRET-KEY-1… (X25519), line 1 = mldsa87seed:<b64> (32-byte seed).
// rustcrypto-wasm reconstructs the full ML-DSA-87 signing key from the seed on each call.
function getMldsaSeed(identityBlob) {
  const line = identityBlob.split('\n')[1] ?? '';
  if (!line.startsWith('mldsa87seed:')) throw new Error('No ML-DSA-87 seed in identity blob');
  return fromB64(line.slice('mldsa87seed:'.length));
}

// ─── Contacts encryption ──────────────────────────────────────────────────────

const ENVELOPE_VER     = 0x01;
const ENVELOPE_HDR_LEN = 1;

function encryptContacts(jsonStr) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const plaintext   = new TextEncoder().encode(jsonStr);
  const noncePlusCt = _xchacha_encrypt(_contactsKeyBytes, plaintext);
  const envelope    = new Uint8Array(ENVELOPE_HDR_LEN + noncePlusCt.length);
  envelope[0]       = ENVELOPE_VER;
  envelope.set(noncePlusCt, ENVELOPE_HDR_LEN);
  return toB64(envelope);
}

function decryptContacts(b64) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const envelope = fromB64(b64);
  if (envelope[0] !== ENVELOPE_VER)
    throw new Error(`Unknown contacts envelope version 0x${envelope[0].toString(16)}.`);
  if (envelope.length < 41)
    throw new Error('Contacts envelope too short — data may be corrupt.');
  const plaintext = _xchacha_decrypt(_contactsKeyBytes, envelope.slice(ENVELOPE_HDR_LEN));
  return new TextDecoder().decode(plaintext);
}

// ─── Identity state ───────────────────────────────────────────────────────────

// _contactsKeyBytes is not persisted to session — it is passed only via UNLOCK
// and lost on SW sleep/wake. PING's hasContactsKey reflects this.
async function ensureIdentity() {
  if (_identity) return true;
  try {
    const d = await chrome.storage.session.get(['age_unlocked', 'age_identity', 'age_contacts', 'age_recipient']);
    if (!d.age_unlocked || !d.age_identity) return false;
    _identity = d.age_identity;
    if (d.age_contacts && typeof d.age_contacts === 'object') _contacts = d.age_contacts;
    if (d.age_recipient) _ageRecipient = d.age_recipient;
    return true;
  } catch { return false; }
}

async function sendUnlockToTab(tabId) {
  if (!_identity) return;
  try {
    await chrome.tabs.sendMessage(tabId, {
      type:         'UNLOCK',
      mldsaSeedB64: toB64(getMldsaSeed(_identity)),
      contacts:     _contacts,
      ageRecipient: _ageRecipient,
    });
  } catch {}
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url?.startsWith('https://discord.com/')) return;
  // Only relay if already live in memory — don't restore from session here.
  // The popup's bgUnlockResume() is responsible for SW revival.
  if (!_identity) return;
  setTimeout(() => sendUnlockToTab(tabId), 800);
});

// ─── Message handler ──────────────────────────────────────────────────────────

// Holding this port keeps the SW alive. Content script reloads on disconnect
// (only occurs on extension reload/update, not normal SW sleep/wake).
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'age-watchdog') return;
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {

  if (msg.type === 'UNLOCK') {
    (async () => {
      try {
        // State is set directly here (not via ensureIdentity) because the
        // popup is the authoritative source at unlock time — no session read needed.
        _identity     = msg.identity;
        _contacts     = msg.contacts     ?? _contacts;
        _ageRecipient = msg.ageRecipient ?? _ageRecipient;
        const tabs = await chrome.tabs.query({ url: 'https://discord.com/*' });
        for (const tab of tabs)
          // .catch() suppresses "no listener" rejections for tabs where the
          // content script hasn't loaded yet — expected, not an error.
          chrome.tabs.sendMessage(tab.id, {
            type:         'UNLOCK',
            mldsaSeedB64: toB64(getMldsaSeed(_identity)),
            contacts:     _contacts,
            ageRecipient: _ageRecipient,
          }).catch(() => {});
        if (msg.contactsKeyB64)
          _contactsKeyBytes = fromB64(msg.contactsKeyB64);
      } catch (e) { console.info('[age] UNLOCK error:', e?.message); }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg.type === 'PING') {
    sendResponse({ ok: true, hasContactsKey: _contactsKeyBytes !== null, hasIdentity: _identity !== null });
    return false;
  }

  if (msg.type === 'RELOCK') {
    _identity = null; _contactsKeyBytes = null; _contacts = {}; _ageRecipient = null;
    chrome.tabs.query({ url: 'https://discord.com/*' }).then(tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, { type: 'RELOCK' }).catch(() => {});
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
    chrome.tabs.query({ url: 'https://discord.com/*' }).then(tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, {
          type: 'CONTACTS_UPDATED', contacts: _contacts, ageRecipient: _ageRecipient,
        }).catch(() => {});
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'ENCRYPT_CONTACTS') {
    (async () => {
      try {
        await _wasmReady;
        sendResponse({ ok: true, ciphertextB64: encryptContacts(msg.json) });
      } catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }

  if (msg.type === 'DECRYPT_CONTACTS') {
    (async () => {
      try {
        await _wasmReady;
        sendResponse({ ok: true, json: decryptContacts(msg.ciphertextB64) });
      } catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }

  // Returns age X25519xMLKEM768 identity line for file-crypto-worker per-message decryption.
  if (msg.type === 'GET_IDENTITY_LINE') {
    (async () => {
      try {
        if (!(await ensureIdentity())) { sendResponse({ ok: false, error: 'locked' }); return; }
        sendResponse({ ok: true, identityLine: _identity.split('\n')[0] });
      } catch (e) { sendResponse({ ok: false, error: e?.message ?? String(e) }); }
    })();
    return true;
  }
});
