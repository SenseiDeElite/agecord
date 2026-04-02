// background.js — Discord Age Encryption service worker
//
// Security boundary: the raw age identity blob and Ed25519 signing key live
// exclusively here.  Content scripts never receive the private key — they send
// plaintext/ciphertext to this worker and receive only the result.
//
// Identity lifecycle
// ──────────────────
//   popup unlocks/generates  →  SET_IDENTITY   →  background stores in memory
//                                                  + chrome.storage.session
//   popup locks / resets     →  CLEAR_IDENTITY →  background wipes memory
//                                                  + chrome.storage.session
//   service worker restarts  →  reads chrome.storage.session on first use
//
// Message protocol (content script → background)
// ───────────────────────────────────────────────
//   { type: 'ENCRYPT', plain, channelId, contactRecipient, selfRecipient }
//       → { ok: true, cipher, sig }  |  { ok: false, error }
//
//   { type: 'DECRYPT', cipher, sig, channelId, contactKey, selfKey }
//       → { ok: true, plain }  |  { ok: false, error }
//       on sig failure: error starts with 'SIG_INVALID:'
//
// Message protocol (popup → background)
// ──────────────────────────────────────
//   { type: 'SET_IDENTITY', identity }   → { ok: true }
//   { type: 'CLEAR_IDENTITY' }           → { ok: true }
//
// Message protocol (background → content script)
// ────────────────────────────────────────────────
//   { type: 'UNLOCK' }           — background is ready, identity loaded
//   { type: 'RELOCK' }           — identity cleared, stop encrypting/decrypting
//   { type: 'CONTACTS_UPDATED' } — reload contacts from storage

'use strict';

// In Chromium, background.js runs as a service worker and must load dependencies
// via importScripts().  In Firefox MV3, background scripts are loaded sequentially
// via the manifest "scripts" array (age.min.js first), so importScripts is not
// needed and may not be available.
if (typeof importScripts === 'function') {
  importScripts('lib/age.min.js');
}

// ─── In-memory identity state ─────────────────────────────────────────────────

let _identity   = null;  // two-line blob: "AGE-SECRET-KEY-1…\ned25519priv:…"
let _signingKey = null;  // CryptoKey (Ed25519 private, non-extractable)

// ─── Restore from session storage after service worker restart ────────────────

async function ensureIdentityLoaded() {
  if (_identity && _signingKey) return true;
  try {
    const data = await chrome.storage.session.get(['age_unlocked', 'age_identity']);
    if (!data.age_unlocked || !data.age_identity) return false;
    await applyIdentity(data.age_identity);
    return !!(_identity && _signingKey);
  } catch {
    return false;
  }
}

async function applyIdentity(identityBlob) {
  const line = identityBlob.split('\n')[1] ?? '';
  if (!line.startsWith('ed25519priv:')) throw new Error('No Ed25519 private key in identity blob');
  const pkcs8 = base64UrlToBytes(line.slice('ed25519priv:'.length));
  _signingKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']
  );
  _identity = identityBlob;
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function importVerifyKey(contactKeyString) {
  const m = contactKeyString.match(/;ed25519:([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  const raw = base64UrlToBytes(m[1]);
  return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
}

async function streamTransform(stream, bytes) {
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
  return out;
}

const compress   = str   => streamTransform(new CompressionStream('deflate-raw'),   new TextEncoder().encode(str));
const decompress = bytes => streamTransform(new DecompressionStream('deflate-raw'), bytes).then(b => new TextDecoder().decode(b));

// ─── Base64 helpers ───────────────────────────────────────────────────────────

function bytesToBase64Disc(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '.').replace(/=/g, '');
}

function base64DiscToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── ENCRYPT handler ──────────────────────────────────────────────────────────

async function handleEncrypt({ plain, channelId, contactRecipient, selfRecipient }) {
  if (!await ensureIdentityLoaded()) throw new Error('Extension is locked.');
  if (!plain || !channelId || !contactRecipient) throw new Error('Missing required fields.');

  const enc = new age.Encrypter();
  enc.addRecipient(contactRecipient.split(';')[0]);
  if (selfRecipient) enc.addRecipient(selfRecipient.split(';')[0]);

  const cipher = bytesToBase64Disc(await enc.encrypt(await compress(plain)));

  // Sign channelId:cipher — channel-binds the signature, blocking cross-channel replay.
  const sigInput = new TextEncoder().encode(`${channelId}:${cipher}`);
  const sigBytes = await crypto.subtle.sign('Ed25519', _signingKey, sigInput);
  // Clamp to 64 bytes — some Chromium builds return 65 bytes from Ed25519 sign.
  const sig = bytesToBase64Disc(new Uint8Array(sigBytes).slice(0, 64));

  return { cipher, sig };
}

// ─── DECRYPT handler (verify then decrypt — atomic, all in trusted context) ───

async function handleVerifyAndDecrypt({ cipher, sig, channelId, contactKey, selfKey }) {
  if (!await ensureIdentityLoaded()) throw new Error('Extension is locked.');
  if (!cipher || !sig || !channelId) throw new Error('Missing required fields.');

  const sigInput = new TextEncoder().encode(`${channelId}:${cipher}`);
  const sigBytes = base64DiscToBytes(sig).slice(0, 64);

  // ── Contact key verification ──────────────────────────────────────────────
  let contactValid  = false;
  let contactKeyErr = null;
  try {
    if (contactKey) {
      const ck = await importVerifyKey(contactKey);
      if (ck) contactValid = await crypto.subtle.verify('Ed25519', ck, sigBytes, sigInput);
    }
  } catch (e) { contactKeyErr = e.message; }

  // ── Self key verification (messages the user sent themselves) ─────────────
  // Cross-channel self-replay is already blocked by channelId being in sigInput.
  let selfValid  = false;
  let selfKeyErr = null;
  if (!contactValid) {
    try {
      if (selfKey) {
        const sk = await importVerifyKey(selfKey);
        if (sk) selfValid = await crypto.subtle.verify('Ed25519', sk, sigBytes, sigInput);
      }
    } catch (e) { selfKeyErr = e.message; }
  }

  if (!contactValid && !selfValid) {
    const reason = contactKeyErr ? `contact key error: ${contactKeyErr}`
                 : selfKeyErr    ? `self key error: ${selfKeyErr}`
                 :                 'possible tampering or cross-channel replay';
    throw new Error('SIG_INVALID:' + reason);
  }

  // ── Decrypt ───────────────────────────────────────────────────────────────
  const dec = new age.Decrypter();
  dec.addIdentity(_identity.split('\n')[0]);
  const plain = await decompress(await dec.decrypt(base64DiscToBytes(cipher), 'uint8array'));
  return { plain };
}

// ─── Message router ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fromDiscord   = !!(sender.tab && sender.url?.startsWith('https://discord.com/'));
  const fromExtension = !sender.tab; // popup has no sender.tab

  if (msg.type === 'SET_IDENTITY') {
    if (!fromExtension) { sendResponse({ ok: false, error: 'Unauthorized' }); return true; }
    applyIdentity(msg.identity)
      .then(() => chrome.storage.session.set({
        age_unlocked: true,
        age_identity: msg.identity,
      }))
      .then(() => sendResponse({ ok: true }))
      .catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'CLEAR_IDENTITY') {
    if (!fromExtension) { sendResponse({ ok: false, error: 'Unauthorized' }); return true; }
    _identity   = null;
    _signingKey = null;
    chrome.storage.session.remove(['age_unlocked', 'age_identity'])
      .then(() => sendResponse({ ok: true }))
      .catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'ENCRYPT') {
    if (!fromDiscord) { sendResponse({ ok: false, error: 'Unauthorized' }); return true; }
    handleEncrypt(msg)
      .then(r => sendResponse({ ok: true, ...r }))
      .catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'DECRYPT') {
    if (!fromDiscord) { sendResponse({ ok: false, error: 'Unauthorized' }); return true; }
    handleVerifyAndDecrypt(msg)
      .then(r => sendResponse({ ok: true, ...r }))
      .catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  // PING — used by content scripts to confirm the ack during tab unlock
  if (msg.type === 'PING') {
    sendResponse({ ok: true });
    return false;
  }
});

// ─── Tab unlock on navigation ─────────────────────────────────────────────────
// When a Discord tab finishes loading, signal the content script that the
// background is ready.  Retries with exponential backoff — no more fragile
// fixed 800ms delay.

async function tryUnlockTab(tabId, attemptsLeft, delay) {
  if (!await ensureIdentityLoaded()) return; // locked, nothing to do

  try {
    await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, { type: 'UNLOCK' }, (response) => {
        if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
        else if (response?.ok) resolve();
        else reject(new Error('no ack'));
      });
    });
    // Ack received — content script is live and unlocked.
  } catch {
    if (attemptsLeft > 0) {
      await new Promise(r => setTimeout(r, delay));
      await tryUnlockTab(tabId, attemptsLeft - 1, delay * 2);
    }
    // All retries exhausted — user can unlock manually via the popup.
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url?.startsWith('https://discord.com/')) return;
  // Short initial delay to let the content script finish its own init.
  setTimeout(() => tryUnlockTab(tabId, 3, 300), 300);
});
