// background.js — Discord Age Encryption service worker
//
// Responsibilities:
//   1. Re-send the signing key bytes to Discord tabs when they finish loading,
//      so the content script is unlocked immediately without reopening the popup.
//   2. Hold the age identity in memory and service DECRYPT_MSG requests from
//      content scripts — the age secret key never flows into the content script.
//
// Key material flow:
//   popup  → (UNLOCK)          → background : full identity blob
//   background → (UNLOCK)      → content    : signingKeyB64 (PKCS8 base64url string)
//   content    → (DECRYPT_MSG) → background → content : plaintext
//
// Note: CryptoKey objects cannot be sent via chrome.tabs.sendMessage — Chrome
// extension IPC serializes via JSON which silently drops CryptoKey fields,
// arriving in the content script as a plain empty object {}.  We send the raw
// base64url PKCS8 bytes instead; the content script imports them into a
// non-extractable CryptoKey locally.

'use strict';

importScripts('lib/age.min.js');

// ─── In-memory identity state ─────────────────────────────────────────────────
// Reconstructed from session storage whenever the service worker wakes after
// being killed by the browser.

let _identity = null;   // raw two-line identity blob

// ─── Helpers ──────────────────────────────────────────────────────────────────

function base64DiscToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Extract the base64url PKCS8 private key string directly from the identity blob.
// This is the raw line already stored in the blob — no crypto needed.
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

// ─── Ensure in-memory state is populated ─────────────────────────────────────
// Called before any operation that needs the identity. If the service worker
// was killed and restarted, _identity is null even though session storage has it.

async function ensureIdentity() {
  if (_identity) return true;
  try {
    const data = await chrome.storage.session.get(['age_unlocked', 'age_identity']);
    if (!data.age_unlocked || !data.age_identity) return false;
    _identity = data.age_identity;
    return true;
  } catch {
    return false;
  }
}

async function decryptPayload(cipherBase64disc) {
  const dec = new age.Decrypter();
  dec.addIdentity(_identity.split('\n')[0]);
  const compressed = await dec.decrypt(base64DiscToBytes(cipherBase64disc), 'uint8array');
  return decompress(compressed);
}

async function reloadDiscordTabs() {
  const tabs = await chrome.tabs.query({ url: 'https://discord.com/*' });
  for (const tab of tabs) chrome.tabs.reload(tab.id);
}

async function sendUnlockToTab(tabId) {
  if (!(await ensureIdentity())) return;
  try {
    const signingKeyB64 = getSigningKeyB64(_identity);
    await chrome.tabs.sendMessage(tabId, { type: 'UNLOCK', signingKeyB64 });
  } catch { /* tab may not have content script yet */ }
}

// ─── Tab update listener ──────────────────────────────────────────────────────

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
        _identity = msg.identity;
        const signingKeyB64 = getSigningKeyB64(_identity);
        const tabs = await chrome.tabs.query({ url: 'https://discord.com/*' });
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, { type: 'UNLOCK', signingKeyB64 },
            () => void chrome.runtime.lastError);
        }
      } catch (e) {
        console.info('[age] background UNLOCK error:', e?.message);
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg.type === 'RELOCK') {
    _identity = null;
    chrome.tabs.query({ url: 'https://discord.com/*' }, tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, { type: 'RELOCK' }, () => void chrome.runtime.lastError);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'RELOAD_DISCORD_TABS') {
    reloadDiscordTabs().catch(() => {});
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'CONTACTS_UPDATED') {
    chrome.tabs.query({ url: 'https://discord.com/*' }, tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, { type: 'CONTACTS_UPDATED' }, () => void chrome.runtime.lastError);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'DECRYPT_MSG') {
    (async () => {
      try {
        if (!(await ensureIdentity())) { sendResponse({ ok: false, error: 'locked' }); return; }
        const plaintext = await decryptPayload(msg.cipher);
        sendResponse({ ok: true, plaintext });
      } catch (e) {
        sendResponse({ ok: false, error: e?.message ?? String(e) });
      }
    })();
    return true;
  }
});
