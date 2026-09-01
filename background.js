/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// background.js — Agecord service worker

// Key flow:
// popup → background: identity blob + contacts key.
// background → content: ML-DSA-87 seed + age identity line.
// popup ↔ background: contacts JSON ↔ ciphertext.

// Message decryption runs in content script (file-crypto-worker.js);
// chrome.storage.session stores transient unlock state securely.

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

// Incremented by handleUnlock/handleRelock. Invalidates in-flight async restores.
let _epoch = 0;

// ─── Base64 helpers ───────────────────────────────────────────────────────────
const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

// ─── XChaCha20-Poly1305 helpers ───────────────────────────────────────────────

// XChaCha20-Poly1305 envelope:
// [version][24-byte nonce][ciphertext+tag]
// Stored as base64 in chrome.storage.local (contactsEnc).

// Note: crypto-worker.js uses a different envelope with embedded salt.
// Here salt is stored separately (contactsSaltB64). Keep formats distinct.

// Identity blob:
// line 0: AGE-SECRET-KEY-1… (X25519)
// line 1: mldsa87seed:<b64> (32-byte seed)
// ML-DSA-87 signing key is rebuilt from seed per call.

function getMldsaSeed(identityBlob) {
  const line = identityBlob.split('\n')[1] ?? '';
  if (!line.startsWith('mldsa87seed:')) throw new Error('No ML-DSA-87 seed in identity blob');
  return fromB64(line.slice('mldsa87seed:'.length));
}

// ─── Contacts encryption ──────────────────────────────────────────────────────

const ENVELOPE_VER      = 0x01;
const ENVELOPE_HDR_LEN  = 1;
const XCHACHA_NONCE_LEN = 24;
const POLY1305_TAG_LEN  = 16;
// Minimum valid envelope: version byte + nonce + at least an empty-plaintext tag.
const MIN_ENVELOPE_LEN  = ENVELOPE_HDR_LEN + XCHACHA_NONCE_LEN + POLY1305_TAG_LEN;

function encryptContacts(jsonStr) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const plaintext   = new TextEncoder().encode(jsonStr);
  const noncePlusCt = xchacha20poly1305_encrypt(_contactsKeyBytes, plaintext);
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
  if (envelope.length < MIN_ENVELOPE_LEN)
    throw new Error('Contacts envelope too short — data may be corrupt.');
  const plaintext = xchacha20poly1305_decrypt(_contactsKeyBytes, envelope.slice(ENVELOPE_HDR_LEN));
  return new TextDecoder().decode(plaintext);
}

// ─── Identity state ───────────────────────────────────────────────────────────

// Keys held in chrome.storage.session; shared by ensureIdentity's read and
// RELOCK's clear so the two can't silently drift out of sync.

// age_contacts_key mirrors _contactsKeyBytes and is written atomically with
// identity so service-worker wake cannot restore them independently.
const SESSION_KEYS = ['age_unlocked', 'age_identity', 'age_contacts', 'age_recipient', 'age_contacts_key'];

// Restores identity, contacts, and key from session storage.
// Discards stale results superseded by RELOCK or a newer UNLOCK.
async function ensureIdentity() {
  if (_identity) return true;
  const myEpoch = _epoch;
  try {
    const d = await chrome.storage.session.get(SESSION_KEYS);
    if (_epoch !== myEpoch) return _identity !== null; // superseded mid-read
    if (!d.age_unlocked || !d.age_identity) return false;
    _identity = d.age_identity;
    if (d.age_contacts && typeof d.age_contacts === 'object') _contacts = d.age_contacts;
    if (d.age_recipient) _ageRecipient = d.age_recipient;
    if (d.age_contacts_key) {
      _contactsKeyBytes?.fill(0);
      _contactsKeyBytes = fromB64(d.age_contacts_key);
    }
    return true;
  } catch (e) {
    console.error('[age] ensureIdentity: session read failed:', e?.message);
    return false;
  }
}

// Shared by the tab-push path (sendUnlockToTab) and the pull-response path
// (handleRequestUnlock) so the two payload shapes can't drift apart.
// Returns null when locked.

// Include identityLine directly to avoid a second request during session restoration.
function buildUnlockPayload() {
  if (!_identity) return null;
  const identityLine = _identity.split('\n')[0];
  if (!identityLine) {
    // Empty identityLine means malformed identity, not a locked state.
    console.error('[age] buildUnlockPayload: identityLine is empty — identity blob is malformed');
  }
  return {
    mldsaSeedB64: toB64(getMldsaSeed(_identity)),
    identityLine,
    contacts:     _contacts,
    ageRecipient: _ageRecipient,
  };
}

// Best-effort push to an open, initialized, idle tab. A single failed
// attempt is sufficient; init-time REQUEST_UNLOCK handles missed pushes.
async function sendUnlockToTab(tabId) {
  const payload = buildUnlockPayload();
  if (!payload) return;
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'UNLOCK', ...payload });
  } catch (e) {
    console.info(`[age] sendUnlockToTab: tab ${tabId} not reachable, will self-heal via its own pull:`, e?.message);
  }
}

// Returns all currently-open Discord tabs.
const getDiscordTabs = () => chrome.tabs.query({ url: 'https://discord.com/*' });

// Fire-and-forget broadcast for RELOCK and CONTACTS_UPDATED.
// No retry needed; payloads are not timing-sensitive.
// Rejections mean no content listener; expected and logged.
async function broadcastToTabs(payload) {
  const tabs = await getDiscordTabs();
  for (const tab of tabs) {
    chrome.tabs.sendMessage(tab.id, payload)
      .catch(e => console.info(`[age] broadcastToTabs: tab ${tab.id} did not receive ${payload.type}:`, e?.message));
  }
}

// ─── Message handlers ──────────────────────────────────────────────────────────

function handleUnlock(msg, _sender, sendResponse) {
  (async () => {
    try {
      // State is set directly here (not via ensureIdentity) because the
      // popup is the authoritative source at unlock time — no session read needed.
      _epoch++; // supersede any in-flight ensureIdentity()/RELOCK race
      _identity     = msg.identity;
      _contacts     = msg.contacts     ?? _contacts;
      _ageRecipient = msg.ageRecipient ?? _ageRecipient;
      if (msg.contactsKeyB64) {
        _contactsKeyBytes?.fill(0);
        _contactsKeyBytes = fromB64(msg.contactsKeyB64);
      }
      // Atomic session write: identity, contacts, recipient, and key stay consistent.
      await chrome.storage.session.set({
        age_unlocked:     true,
        age_identity:     _identity,
        age_contacts:     _contacts,
        age_recipient:    _ageRecipient,
        age_contacts_key: _contactsKeyBytes ? toB64(_contactsKeyBytes) : null,
      });
      // Best-effort push to every open Discord tab. Only load-bearing for
      // tabs that are already fully loaded and idle — a tab that's still
      // loading will get this same state itself via its own boot-time
      // REQUEST_UNLOCK pull, whether or not this push reaches it in time.
      const tabs = await getDiscordTabs();
      await Promise.all(tabs.map(tab => sendUnlockToTab(tab.id)));
      sendResponse({ ok: true });
    } catch (e) {
      console.error('[age] UNLOCK error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

function handlePing(_msg, _sender, sendResponse) {
  (async () => {
    await ensureIdentity();
    sendResponse({ ok: true, hasContactsKey: _contactsKeyBytes !== null, hasIdentity: _identity !== null });
  })();
  return true;
}

function handleRelock(_msg, _sender, sendResponse) {
  _epoch++; // supersede any in-flight ensureIdentity() read from an UNLOCK/PING/etc.
  _identity = null;
  _contactsKeyBytes?.fill(0);
  _contactsKeyBytes = null;
  _contacts = {}; _ageRecipient = null;
  // Clear session storage before async work so concurrent ensureIdentity() sees
  // age_unlocked=false, aborts, and can't restore stale identity after relock.
  
  // The epoch bump above additionally covers reads that already passed that
  // check and are waiting on their own .get() to resolve.
  chrome.storage.session.remove(SESSION_KEYS)
    .catch(e => console.error('[age] RELOCK session clear failed:', e?.message));
  broadcastToTabs({ type: 'RELOCK' });
  sendResponse({ ok: true });
  return false;
}

function handleReloadDiscordTabs(_msg, _sender, sendResponse) {
  getDiscordTabs()
    .then(tabs => tabs.forEach(t => chrome.tabs.reload(t.id)))
    .catch(e => console.error('[age] RELOAD_DISCORD_TABS failed:', e?.message));
  sendResponse({ ok: true });
  return false;
}

function handleContactsUpdated(msg, _sender, sendResponse) {
  if (msg.contacts)     _contacts     = msg.contacts;
  if (msg.ageRecipient) _ageRecipient = msg.ageRecipient;
  broadcastToTabs({ type: 'CONTACTS_UPDATED', contacts: _contacts, ageRecipient: _ageRecipient });
  // Sync session storage while unlocked; abort if RELOCK superseded this update.
  if (_identity) {
    chrome.storage.session.set({ age_contacts: _contacts, age_recipient: _ageRecipient })
      .catch(e => console.error('[age] CONTACTS_UPDATED session write failed:', e?.message));
  }
  sendResponse({ ok: true });
  return false;
}

function handleEncryptContacts(msg, _sender, sendResponse) {
  (async () => {
    try {
      await _wasmReady;
      await ensureIdentity(); // restore contacts key too if the SW just woke up
      sendResponse({ ok: true, ciphertextB64: encryptContacts(msg.json) });
    } catch (e) {
      console.error('[age] ENCRYPT_CONTACTS error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

function handleDecryptContacts(msg, _sender, sendResponse) {
  (async () => {
    try {
      await _wasmReady;
      await ensureIdentity(); // restore contacts key too if the SW just woke up
      sendResponse({ ok: true, json: decryptContacts(msg.ciphertextB64) });
    } catch (e) {
      console.error('[age] DECRYPT_CONTACTS error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

// Pull-based counterpart to sendUnlockToTab. Called at content-script init;
// responds on the request/response channel, avoiding a second sendMessage
// and any listener-readiness race.
function handleRequestUnlock(_msg, _sender, sendResponse) {
  (async () => {
    try {
      const hasIdentity = await ensureIdentity();
      if (!hasIdentity) { sendResponse({ ok: false }); return; }
      const payload = buildUnlockPayload();
      if (!payload) { sendResponse({ ok: false }); return; }
      sendResponse({ ok: true, ...payload });
    } catch (e) {
      console.error('[age] REQUEST_UNLOCK error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

const handlers = {
  UNLOCK:               handleUnlock,
  PING:                 handlePing,
  RELOCK:               handleRelock,
  RELOAD_DISCORD_TABS:  handleReloadDiscordTabs,
  CONTACTS_UPDATED:     handleContactsUpdated,
  ENCRYPT_CONTACTS:     handleEncryptContacts,
  DECRYPT_CONTACTS:     handleDecryptContacts,
  REQUEST_UNLOCK:       handleRequestUnlock,
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg?.type) return false;
  const handler = handlers[msg.type];
  if (!handler) return false;
  return handler(msg, sender, sendResponse);
});
