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
// browser.storage.session stores transient unlock state securely.

'use strict';

import { init as _rustcryptoInit, xchacha20poly1305_encrypt }
  from '../lib/agecord-encrypt.min.js';

// init() is idempotent. Fire it immediately so WASM is ready before any message
// arrives, but service workers forbid top-level await — store the Promise instead.
const _wasmReady = _rustcryptoInit();

let _identity          = null;
let _contactsKeyBytes  = null; // raw Uint8Array, derived by popup's crypto-worker
let _contacts          = {};
let _agecordRecipient      = null;
let _globalOn          = true; // owned here; copied in from the popup

// Restrict storage.local to trusted contexts.
// The promise starts at module load (service workers forbid top-level
// await), is not awaited by anything, and is re-applied on every worker start.
(async () => {
  try {
    const area = browser.storage.local;
    if (typeof area.setAccessLevel !== 'function') return false;   // feature absent
    await area.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    return true;
  } catch (e) {
    console.info('[agecord] storage.local setAccessLevel failed:', e?.message);
    return false;
  }
})();

// Incremented by handleUnlock/handleRelock. Invalidates in-flight async restores.
let _epoch = 0;

// ─── Base64 helpers ───────────────────────────────────────────────────────────
const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

// ─── XChaCha20-Poly1305 helpers ───────────────────────────────────────────────

// XChaCha20-Poly1305 envelope:
// [version][24-byte nonce][ciphertext+tag]
// Stored as base64 in browser.storage.local (contactsEnc).

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

function encryptContacts(jsonStr) {
  if (!_contactsKeyBytes) throw new Error('Contacts key not available — extension locked.');
  const plaintext   = new TextEncoder().encode(jsonStr);
  const noncePlusCt = xchacha20poly1305_encrypt(_contactsKeyBytes, plaintext);
  const envelope    = new Uint8Array(ENVELOPE_HDR_LEN + noncePlusCt.length);
  envelope[0]       = ENVELOPE_VER;
  envelope.set(noncePlusCt, ENVELOPE_HDR_LEN);
  return toB64(envelope);
}

// ─── Identity state ───────────────────────────────────────────────────────────

// Keys held in browser.storage.session; shared by ensureIdentity's read and
// RELOCK's clear so the two can't silently drift out of sync.

// agecord_contacts_key mirrors _contactsKeyBytes and is written atomically with
// identity so service-worker wake cannot restore them independently.
const SESSION_KEYS = ['agecord_unlocked', 'agecord_identity', 'agecord_contacts', 'agecord_recipient', 'agecord_contacts_key', 'agecord_global_on'];

// Restores identity, contacts, and key from session storage.
// Discards stale results superseded by RELOCK or a newer UNLOCK.
async function ensureIdentity() {
  if (_identity) return true;
  const myEpoch = _epoch;
  try {
    const d = await browser.storage.session.get(SESSION_KEYS);
    if (_epoch !== myEpoch) return _identity !== null; // superseded mid-read
    if (!d.agecord_unlocked || !d.agecord_identity) return false;
    _identity = d.agecord_identity;
    if (d.agecord_contacts && typeof d.agecord_contacts === 'object') _contacts = d.agecord_contacts;
    if (d.agecord_recipient) _agecordRecipient = d.agecord_recipient;
    if (typeof d.agecord_global_on === 'boolean') _globalOn = d.agecord_global_on;
    if (d.agecord_contacts_key) {
      _contactsKeyBytes?.fill(0);
      _contactsKeyBytes = fromB64(d.agecord_contacts_key);
    }
    return true;
  } catch (e) {
    console.error('[agecord] ensureIdentity: session read failed:', e?.message);
    return false;
  }
}

// Shared by the tab-push path (sendUnlockToTab) and the pull-response path
// (handleRequestUnlock) so the two payload shapes can't drift apart.
// Returns null when locked.

// Include identityLine directly to avoid a second request during session restoration.
function buildUnlockPayload() {
  if (!_identity) return null;
  try {
    const identityLine = _identity.split('\n')[0];
    if (!identityLine) {
      // Empty identityLine means malformed identity, not a locked state.
      console.error('[agecord] buildUnlockPayload: identityLine is empty — identity blob is malformed');
    }
    return {
      mldsaSeedB64: toB64(getMldsaSeed(_identity)),
      identityLine,
      contacts:     _contacts,
      agecordRecipient: _agecordRecipient,
      globalOn:     _globalOn,
    };
  } catch (e) {
    // A malformed blob must not throw out of the callers.
    console.error('[agecord] buildUnlockPayload failed:', e?.message);
    return null;
  }
}

// Best-effort push to an open, initialized, idle tab. A single failed
// attempt is sufficient; init-time REQUEST_UNLOCK handles missed pushes.
async function sendUnlockToTab(tabId) {
  const payload = buildUnlockPayload();
  if (!payload) return;
  try {
    await browser.tabs.sendMessage(tabId, { type: 'UNLOCK', ...payload });
  } catch (e) {
    console.info(`[agecord] sendUnlockToTab: tab ${tabId} not reachable, will self-heal via its own pull:`, e?.message);
  }
}

// Returns all currently-open Discord tabs.
const getDiscordTabs = () => browser.tabs.query({ url: 'https://discord.com/*' });

// Fire-and-forget broadcast for RELOCK and CONTACTS_UPDATED.
// No retry needed; payloads are not timing-sensitive.
// Rejections mean no content listener; expected and logged.
async function broadcastToTabs(payload) {
  const tabs = await getDiscordTabs();
  for (const tab of tabs) {
    browser.tabs.sendMessage(tab.id, payload)
      .catch(e => console.info(`[agecord] broadcastToTabs: tab ${tab.id} did not receive ${payload.type}:`, e?.message));
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
      _agecordRecipient = msg.agecordRecipient ?? _agecordRecipient;
      if (typeof msg.globalOn === 'boolean') _globalOn = msg.globalOn;
      if (msg.contactsKeyB64) {
        _contactsKeyBytes?.fill(0);
        _contactsKeyBytes = fromB64(msg.contactsKeyB64);
      }
      // Atomic session write; roll back if _epoch changes during the write to prevent
      // RELOCK races from resurrecting agecord_unlocked state.
      const myEpoch = _epoch;
      // agecord_contacts_key is written only when a key is held: an UNLOCK without
      // one must never overwrite a key that is already in the session.
      // agecord_contacts is written separately so an over-quota list
      // drops only the mirror, never the unlock.
      await browser.storage.session.set({
        agecord_unlocked:  true,
        agecord_identity:  _identity,
        agecord_recipient: _agecordRecipient,
        agecord_global_on: _globalOn,
        ...(_contactsKeyBytes ? { agecord_contacts_key: toB64(_contactsKeyBytes) } : {}),
      });
      try {
        await browser.storage.session.set({ agecord_contacts: _contacts });
      } catch (e) {
        console.warn('[agecord] UNLOCK: contacts mirror not stored in session:', e?.message);
        await browser.storage.session.remove('agecord_contacts').catch(() => {});
      }
      if (_epoch !== myEpoch) {
        // Superseded during the write; remove the stale identity from storage.
        await browser.storage.session.remove(SESSION_KEYS)
          .catch(e => console.error('[agecord] UNLOCK post-RELOCK cleanup failed:', e?.message));
        sendResponse({ ok: false, error: 'superseded' });
        return;
      }
      // Best-effort push to every open Discord tab. Only load-bearing for
      // tabs that are already fully loaded and idle — a tab that's still
      // loading will get this same state itself via its own boot-time
      // REQUEST_UNLOCK pull, whether or not this push reaches it in time.
      const tabs = await getDiscordTabs();
      await Promise.all(tabs.map(tab => sendUnlockToTab(tab.id)));
      sendResponse({ ok: true });
    } catch (e) {
      console.error('[agecord] UNLOCK error:', e?.message);
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
  _contacts = {}; _agecordRecipient = null; _globalOn = true;
  // Clear session storage before async work so concurrent ensureIdentity() sees
  // agecord_unlocked=false, aborts, and can't restore stale identity after relock.
  
  // The epoch bump above additionally covers reads that already passed that
  // check and are waiting on their own .get() to resolve.
  browser.storage.session.remove(SESSION_KEYS)
    .catch(e => console.error('[agecord] RELOCK session clear failed:', e?.message));
  broadcastToTabs({ type: 'RELOCK' })
    .catch(e => console.error('[agecord] RELOCK broadcast failed:', e?.message));
  sendResponse({ ok: true });
  return false;
}

function handleReloadDiscordTabs(_msg, _sender, sendResponse) {
  (async () => {
    try {
      const tabs = await getDiscordTabs();
      for (const t of tabs) browser.tabs.reload(t.id);
    } catch (e) {
      console.error('[agecord] RELOAD_DISCORD_TABS failed:', e?.message);
    }
  })();
  sendResponse({ ok: true });
  return false;
}

function handleContactsUpdated(msg, _sender, sendResponse) {
  (async () => {
    try {
      // A freshly woken worker has no state yet: restore it first, otherwise the
      // session write below would be skipped and a later restore would bring
      // back stale values.
      await ensureIdentity();
      if (!_identity) { sendResponse({ ok: false, error: 'locked' }); return; }

      if (msg.contacts && typeof msg.contacts === 'object' && !Array.isArray(msg.contacts))
        _contacts = msg.contacts;
      if (typeof msg.agecordRecipient === 'string' && msg.agecordRecipient) _agecordRecipient = msg.agecordRecipient;
      if (typeof msg.globalOn === 'boolean') _globalOn = msg.globalOn;

      // Sync session storage; re-check _epoch after set() so a RELOCK race
      // cannot resurrect the data.
      const myEpoch = _epoch;
      try {
        await browser.storage.session.set({
          agecord_recipient: _agecordRecipient,
          agecord_global_on: _globalOn,
        });
        try {
          await browser.storage.session.set({ agecord_contacts: _contacts });
        } catch (e) {
          console.warn('[agecord] CONTACTS_UPDATED: contacts mirror not stored in session:', e?.message);
          await browser.storage.session.remove('agecord_contacts').catch(() => {});
        }
        if (_epoch !== myEpoch) {
          await browser.storage.session.remove(SESSION_KEYS);
        }
      } catch (e) {
        console.error('[agecord] CONTACTS_UPDATED session sync failed:', e?.message);
      }
      broadcastToTabs({
        type: 'CONTACTS_UPDATED',
        contacts: _contacts, agecordRecipient: _agecordRecipient, globalOn: _globalOn,
      });
      sendResponse({ ok: true });
    } catch (e) {
      console.error('[agecord] CONTACTS_UPDATED error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

function handleEncryptContacts(msg, _sender, sendResponse) {
  (async () => {
    try {
      await _wasmReady;
      await ensureIdentity(); // restore contacts key too if the SW just woke up
      sendResponse({ ok: true, ciphertextB64: encryptContacts(msg.json) });
    } catch (e) {
      console.error('[agecord] ENCRYPT_CONTACTS error:', e?.message);
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
      console.error('[agecord] REQUEST_UNLOCK error:', e?.message);
      sendResponse({ ok: false, error: e?.message ?? String(e) });
    }
  })();
  return true;
}

const handlers = {
  __proto__:            null, // no inherited keys (toString, constructor, …) as handler names
  UNLOCK:               handleUnlock,
  PING:                 handlePing,
  RELOCK:               handleRelock,
  RELOAD_DISCORD_TABS:  handleReloadDiscordTabs,
  CONTACTS_UPDATED:     handleContactsUpdated,
  ENCRYPT_CONTACTS:     handleEncryptContacts,
  REQUEST_UNLOCK:       handleRequestUnlock,
};

// ─── Sender policy ────────────────────────────────────────────────────────────

 // runtime.onMessage is limited to this extension's contexts; external senders
// use onMessageExternal. Enforce explicit sender policies because content
// scripts on discord.com process untrusted input.

// Default-deny: each type requires a handler and a SENDER_POLICY entry.
// Null-prototype tables prevent inherited keys such as "toString" and "__proto__".

const POPUP_URL = browser.runtime.getURL('popup/popup.html');
const DISCORD_ORIGIN = 'https://discord.com';

// Exact page match, ignoring query/hash. popup/import-helper.html is excluded.
const isPopup = (sender) =>
  // Standard: RFC 3986 §3.3, a path ends at the first "?" or "#"
  typeof sender?.url === 'string' && sender.url.split(/[?#]/)[0] === POPUP_URL;

// Top-frame content script on discord.com. Check sender.origin
// instead of the path: Discord is a SPA and routes can change
// before boot-time pulls. The manifest restricts injection to /channels/*;
// this check excludes extension pages, child frames, and lookalike hosts.
// chrome-extension: and moz-extension: origins cannot match.
const isDiscordTopFrame = (sender) =>
  !!sender?.tab && sender.frameId === 0 && sender.origin === DISCORD_ORIGIN;

const SENDER_POLICY = {
  __proto__:           null,
  UNLOCK:              isPopup,
  RELOCK:              isPopup,
  ENCRYPT_CONTACTS:    isPopup,
  CONTACTS_UPDATED:    isPopup,
  PING:                isPopup,
  RELOAD_DISCORD_TABS: isPopup,
  REQUEST_UNLOCK:      isDiscordTopFrame,
};

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const type = msg?.type;
  if (typeof type !== 'string') return false;
  const handler = handlers[type];
  if (!handler) return false;
  const allowed = SENDER_POLICY[type];
  if (!allowed) {
    console.error(`[agecord] ${type} has a handler but no SENDER_POLICY entry; rejected`);
    return false;
  }
  if (!allowed(sender)) {
    console.warn(`[agecord] ${type} rejected: unauthorized sender`);
    return false;
  }
  return handler(msg, sender, sendResponse);
});
