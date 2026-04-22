// content.js — Discord Age Encryption
//
// Wire format : [age]:<base64disc_payload>:<base64disc_ed25519_sig>
// Crypto      : age-encryption (X25519 + ChaCha20-Poly1305) + Ed25519 signatures
// Compression : deflate-raw applied to plaintext before encryption
// Sig input   : UTF-8("<channelId>:<cipher>")            — contacts & groups
//             : UTF-8("<serverId>:<channelId>:<cipher>") — servers
// Encoding    : both cipher and sig use the "disc" base64 alphabet (+ → -  / → .)
//               so that neither field ever contains _ which Discord renders as
//               underline markup and strips from the DOM.
//
// Decryption is delegated to the background service worker so the raw age
// identity never enters the content script's memory.
//
// Contacts shape (v2): { [uuid]: { id, type, channelId?, serverId?, username?,
//                                  name?, ageRecipient?, memberIds?, enabled } }
// Contacts and groups looked up by channelId field; servers by serverId.

import { Encrypter } from '../lib/age.min.js';
import { EMOJI_MAP } from './emoji_map.js';

const PREFIX = '[age]';

// _decryptedCache: Map<msgId (li.id), plaintext>
// Keyed on stable li.id so React DOM reconciliation can re-render instantly.
const _processedIds   = new Set();
const _decryptedCache = new Map();
// _inFlight: Set<msgId> — prevents two concurrent async decrypt IIFEs for the
// same message when the MutationObserver fires multiple times before the first
// IIFE completes (e.g. React reconciliation re-adding the same node).
const _inFlight = new Set();

// _outgoingCache: Map<cipherBase64disc, { plaintext, channelId }>
// Populated when we send a message; lets us render our own message immediately
// without a background decrypt round-trip. channelId is stored so the lookup
// can verify the cipher belongs to the same channel before skipping sig-verify.
// TTL: 8 s.
const _outgoingCache = new Map();

let _signingKey   = null;
let _selfRecipient = null;  // own age public key, received at UNLOCK time
let _contacts     = {};
let _globalOn     = true;
let _msgObserver  = null;
// _generation: incremented on every RELOCK and UNLOCK so that async IIFEs
// spawned under a previous lock state silently no-op when they complete
// rather than overwriting DOM that a newer cycle has already written.
let _generation   = 0;

const sleep    = ms => new Promise(r => setTimeout(r, ms));
const localGet = keys => new Promise(r => chrome.storage.local.get(keys, r));

// ─── DOM helpers ─────────────────────────────────────────────────────────────

function getTextbox()     { return document.querySelector('[data-slate-editor="true"]'); }
function getMessageList() { return document.querySelector('ol[data-list-id="chat-messages"]'); }

function getCurrentChannelId() {
  const m = location.pathname.match(/\/channels\/[^/]+\/(\d+)/);
  return m ? m[1] : null;
}

function getCurrentServerId() {
  const m = location.pathname.match(/\/channels\/(\d+)\/\d+/);
  return m ? m[1] : null;
}

// Returns { entry, channelId } for the current URL, or null if none matches or
// the matching entry is disabled. channelId drives the Ed25519 signature input
// for all entry types. For server entries, entry.serverId is also included in
// the sig input to bind the signature to the specific server+channel pair.
function getActiveEntry() {
  const channelId = getCurrentChannelId();
  const serverId  = getCurrentServerId();

  if (serverId) {
    for (const entry of Object.values(_contacts)) {
      if (entry.type === 'server' && entry.serverId === serverId && entry.enabled)
        return { entry, channelId };
    }
  }

  if (channelId) {
    for (const entry of Object.values(_contacts)) {
      if ((entry.type === 'contact' || !entry.type) && entry.channelId === channelId && entry.enabled)
        return { entry, channelId };
      if (entry.type === 'group' && entry.channelId === channelId && entry.enabled)
        return { entry, channelId };
    }
  }
  return null;
}

function isEncryptionActive() {
  return !!(_signingKey && getActiveEntry() && _globalOn);
}

// ─── Enter key interception ───────────────────────────────────────────────────

function attachEnterHook() {
  const tb = getTextbox();
  if (!tb || tb._ageKeyHandler) return;
  tb._ageKeyHandler = (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e.altKey) return;
    if (document.querySelector('[role="listbox"]')) return;
    const raw = tb.innerText?.trim() ?? '';
    if (!raw) return;
    if (raw.startsWith(PREFIX)) return;
    if (!isEncryptionActive()) return;
    e.preventDefault();
    e.stopPropagation();
    handleEncryptClick();
  };
  tb.addEventListener('keydown', tb._ageKeyHandler, { capture: true });
}

function detachEnterHook() {
  const tb = getTextbox();
  if (tb?._ageKeyHandler) {
    tb.removeEventListener('keydown', tb._ageKeyHandler, { capture: true });
    delete tb._ageKeyHandler;
  }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function importVerifyKey(contactKeyString) {
  const m = contactKeyString.match(/;ed25519:([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  const raw = base64UrlToBytes(m[1]);
  return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
}

// ─── Encryption (outgoing) ────────────────────────────────────────────────────

async function encryptMessage(plaintext, entry) {
  const enc = new Encrypter();
  if (entry.type === 'contact' || !entry.type) {
    enc.addRecipient(entry.ageRecipient.split(';')[0]);
  } else {
    for (const memberUUID of (entry.memberIds ?? [])) {
      const member = _contacts[memberUUID];
      if (member?.ageRecipient) enc.addRecipient(member.ageRecipient.split(';')[0]);
    }
  }
  if (_selfRecipient) enc.addRecipient(_selfRecipient.split(';')[0]);
  return bytesToBase64Disc(await enc.encrypt(await compress(plaintext)));
}

// ─── Compression ─────────────────────────────────────────────────────────────

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

const compress = str => streamTransform(
  new CompressionStream('deflate-raw'), new TextEncoder().encode(str));

// ─── Base64 variants ──────────────────────────────────────────────────────────
// "Disc" variant (+ → -  / → .) : used for ALL wire-format fields (cipher + sig).
//   Dot never appears in standard base64 and triggers no Discord markdown.
//   Underscore-free, so __ can never corrupt the DOM via Discord underline markup.
// "Url"  variant (+ → -  / → _) : used only for key material stored outside the
//   wire format (Ed25519 public keys in contact strings, PKCS8 in identity blob).

function bytesToBase64Url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64Disc(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '.').replace(/=/g, '');
}

function base64DiscToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─── Send ─────────────────────────────────────────────────────────────────────
// Plaintext is inserted via synthetic ClipboardEvent — Slate serialises from its
// internal model, not the DOM, so execCommand('insertText') sends the wrong text.

async function pasteIntoEditor(text) {
  const tb = getTextbox();
  if (!tb) return;
  tb.focus();
  await sleep(20);
  document.execCommand('selectAll', false);
  await sleep(20);
  const dt = new DataTransfer();
  dt.setData('text/plain', text);
  tb.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  await sleep(120);
}

let _sending = false;

async function handleEncryptClick() {
  if (_sending) return;
  if (!isEncryptionActive()) return;
  const active = getActiveEntry();
  const plain  = getTextbox()?.innerText?.trim();
  if (!plain || !active) return;
  const { entry, channelId } = active;
  _sending = true;
  try {
    const cipher = await encryptMessage(plain, entry);

    const sigInput = (entry.type === 'server')
      ? new TextEncoder().encode(`${entry.serverId}:${channelId}:${cipher}`)
      : new TextEncoder().encode(`${channelId}:${cipher}`);
    const sigBytes = await crypto.subtle.sign('Ed25519', _signingKey, sigInput);
    // Clamp to 64 bytes — some Chromium builds return 65 bytes from Ed25519 sign.
    const sig = bytesToBase64Disc(new Uint8Array(sigBytes).slice(0, 64));

    // Cache own outgoing message by cipher so we can render it immediately
    // when it echoes back in the message list, without a background decrypt.
    // channelId is stored alongside so the cache lookup can verify the message
    // belongs to the same channel before bypassing signature verification.
    _outgoingCache.set(cipher, { plaintext: plain, channelId });
    setTimeout(() => _outgoingCache.delete(cipher), 8000);

    await pasteIntoEditor(`${PREFIX}:${cipher}:${sig}`);
  } catch (err) {
    console.error('[age] encrypt error:', err);
  } finally {
    _sending = false;
  }
}

// ─── Receive ──────────────────────────────────────────────────────────────────

function waitForMessageList(onReady) {
  const list = getMessageList();
  if (list) { attachMsgObserver(list); scanExisting(); onReady?.(); return; }
  const iv = setInterval(() => {
    const list = getMessageList();
    if (list) { clearInterval(iv); attachMsgObserver(list); scanExisting(); onReady?.(); }
  }, 400);
}

function attachMsgObserver(list) {
  _msgObserver?.disconnect();
  _msgObserver = new MutationObserver(mutations => {
    let dirty = false;
    for (const { addedNodes } of mutations) {
      for (const node of addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches?.('li[id^="chat-messages-"]')) {
          processMessageNode(node); dirty = true;
        } else {
          node.querySelectorAll?.('li[id^="chat-messages-"]').forEach(li => { processMessageNode(li); dirty = true; });
          if (node.matches?.('[id^="message-content-"]')) {
            const li = node.closest('li');
            if (li) { processMessageNode(li); dirty = true; }
          }
          node.querySelectorAll?.('[id^="message-content-"]').forEach(el => {
            const li = el.closest('li');
            if (li) { processMessageNode(li); dirty = true; }
          });
        }
      }
    }
    if (dirty) sanitizeReplyPreviews();
  });
  _msgObserver.observe(list, { childList: true, subtree: true });
}

function scanExisting() {
  document.querySelectorAll('li[id^="chat-messages-"]').forEach(processMessageNode);
  sanitizeReplyPreviews();
}

function sanitizeReplyPreviews() {
  document.querySelectorAll('[class*="repliedText"] [id^="message-content-"]').forEach(el => {
    if (el.dataset.agePreviewMasked || !el.textContent.includes(PREFIX)) return;
    el.textContent = '🔒 Encrypted message';
    el.style.opacity = '0.6';
    el.dataset.agePreviewMasked = '1';
  });
}

function rescanPending() {
  document.querySelectorAll('[id^="message-content-"][data-age-raw]').forEach(el => {
    if (el.closest('[class*="repliedText"]') || el.closest('[class*="replyPreview"]')) return;
    if (el.dataset.ageState === 'ok') return;
    const li = el.closest('li[id^="chat-messages-"]');
    if (li) processMessageNode(li);
  });
}

function processMessageNode(li) {
  const el = [...li.querySelectorAll('[id^="message-content-"]')].find(e =>
    !e.closest('[class*="repliedText"]') &&
    !e.closest('[class*="replyPreview"]')
  );
  if (!el) return;

  const msgId = li.id;

  if (_processedIds.has(msgId)) {
    const cached = _decryptedCache.get(msgId);
    // Always re-render from cache even if ageState is already 'ok': Discord's
    // React renderer can replace the message-content element with a fresh node
    // that shares the same li.id but has no ageState or content yet.  The check
    // against 'ok' would pass on the OLD node and leave the NEW node blank.
    if (cached) renderDecrypted(el, cached);
    return;
  }

  // Read text before any async work. If already stashed, use that.
  const text = el.dataset.ageRaw ?? directTextContent(el).trim();
  if (!text.startsWith(PREFIX)) return;

  const m = text.match(/^\[age\]:([A-Za-z0-9\-.]+):([A-Za-z0-9\-.]+)$/);
  if (!m) return;

  // Stash raw wire text and IMMEDIATELY blank the element so raw ciphertext
  // is never visible — all paths below replace it with a proper status string
  // or decrypted content before any async work yields the thread.
  el.dataset.ageRaw = text;
  el.textContent = '';

  if (!_signingKey || !_globalOn) {
    markMessage(el, !_signingKey ? '🔒 Unlock extension to decrypt.' : '🔒 Decryption disabled.', 'pending');
    return;
  }

  const cipher = m[1];
  const outgoingEntry = _outgoingCache.get(cipher);
  if (outgoingEntry !== undefined) {
    // Only render from cache if this message appeared in the same channel it
    // was sent in — a replayed cipher in a different channel must not bypass
    // the signature check via the outgoing cache short-circuit.
    const activeForCache = getActiveEntry();
    if (activeForCache && outgoingEntry.channelId === activeForCache.channelId) {
      _processedIds.add(msgId);
      _decryptedCache.set(msgId, outgoingEntry.plaintext);
      renderDecrypted(el, outgoingEntry.plaintext);
      return;
    }
  // channelId mismatch — fall through to normal sig-verify + decrypt path.
  }

  // Guard against concurrent async IIFEs for the same message.
  // React reconciliation can fire the MutationObserver multiple times for the
  // same li before the first decrypt round-trip completes, which would cause
  // a second IIFE to race to getActiveEntry() and potentially read a stale URL.
  if (_inFlight.has(msgId)) return;
  _inFlight.add(msgId);

  // Capture the active entry SYNCHRONOUSLY before yielding the thread.
  // Inside an async IIFE, location.pathname may have changed due to SPA
  // navigation — capturing here guarantees we use the URL that was current
  // when this message node was observed.
  const capturedActive = getActiveEntry();

  // Capture the current generation so this IIFE can detect if a RELOCK or
  // UNLOCK has occurred while it was awaiting crypto/IPC work.  If the
  // generation changes, our results are stale and must not touch the DOM.
  const capturedGeneration = _generation;

  // Leave element blank while decryption is in-flight — the raw ciphertext
  // was already cleared above and showing "Decrypting…" is unreliable.
  el.textContent = '';

  (async () => {
    try {
    // Bail out if a RELOCK/UNLOCK cycle invalidated this IIFE's context.
    if (_generation !== capturedGeneration) return;

    const active = capturedActive;

    if (!active) {
      markMessage(el, '⚠️ No entry configured for this channel.', 'warn');
      return;
    }

    const { entry, channelId } = active;
    const sig      = m[2];
    const sigInput = (entry.type === 'server')
      ? new TextEncoder().encode(`${entry.serverId}:${channelId}:${cipher}`)
      : new TextEncoder().encode(`${channelId}:${cipher}`);
    const sigBytes = base64DiscToBytes(sig).slice(0, 64); // clamp for Chromium

    // Build the list of candidate verify keys depending on entry type.
    // Contact: contact key + own key. Group/server: all member keys + own key — try each in turn.
    // Own key is always included so that our own messages verify correctly once
    // the 8-second outgoing cache has expired (e.g. after a channel switch or reload).
    let candidateKeys; // Array<CryptoKey>
    if (entry.type === 'contact' || !entry.type) {
      const keyPromises = [importVerifyKey(entry.ageRecipient).catch(() => null)];
      if (_selfRecipient) {
        keyPromises.push(importVerifyKey(_selfRecipient).catch(() => null));
      }
      candidateKeys = (await Promise.all(keyPromises)).filter(Boolean);
    } else {
      // Group or server: collect Ed25519 verify keys from all members,
      // plus our own public key so our own outgoing messages verify correctly
      // even after the outgoing cache has expired (e.g. after a channel switch).
      const memberIds = entry.memberIds ?? [];
      const keyPromises = memberIds.map(uuid => {
        const member = _contacts[uuid];
        return member?.ageRecipient
          ? importVerifyKey(member.ageRecipient).catch(() => null)
          : Promise.resolve(null);
      });
      // Add own key if available — stored in _selfRecipient as the full
    // recipient string (age1…;ed25519:…), same format as contact keys.
    if (_selfRecipient) {
       keyPromises.push(importVerifyKey(_selfRecipient).catch(() => null));
    }
      candidateKeys = (await Promise.all(keyPromises)).filter(Boolean);
    }

    // Re-check generation after the first set of async calls (importKey).
    if (_generation !== capturedGeneration) return;

    if (candidateKeys.length === 0) {
      markMessage(el, '⚠️ No member keys available to verify signature.', 'warn');
      return;
    }

    // Try each candidate key. First verification success = valid signature.
    let sigValid = false;
    for (const key of candidateKeys) {
      try {
        if (await crypto.subtle.verify('Ed25519', key, sigBytes, sigInput)) {
          sigValid = true;
          break;
        }
      } catch { /* key format mismatch — continue */ }
    }

    // Re-check generation after verify (another async boundary).
    if (_generation !== capturedGeneration) return;

    if (!sigValid) {
      console.info('[age] signature mismatch — msgId', msgId);
      markMessage(el, '🔴 Signature invalid — possible tampering.', 'error');
      return;
    }

    // Signature is valid — delegate decryption to the background.
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'DECRYPT_MSG', cipher });
      // Final generation check — RELOCK may have arrived while we awaited IPC.
      if (_generation !== capturedGeneration) return;
      if (!resp?.ok) {
        if (resp?.error === 'locked') {
          markMessage(el, '🔒 Unlock extension to decrypt.', 'pending');
        } else {
          console.info('[age] decrypt failed — msgId', msgId, resp?.error);
          markMessage(el, '🔓 Could not decrypt.', 'error');
        }
        return;
      }
      _processedIds.add(msgId);
      _decryptedCache.set(msgId, resp.plaintext);
      renderDecrypted(el, resp.plaintext);
    } catch (err) {
      console.info('[age] decrypt IPC error — msgId', msgId, err?.message);
      markMessage(el, '🔓 Could not decrypt.', 'error');
    }
    } finally {
      _inFlight.delete(msgId);
    }
  })();
}

function directTextContent(el) {
  let text = '';
  for (const node of el.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) {
      text += node.textContent;
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      const cls  = node.className ?? '';
      const skip = node.getAttribute('data-type') === 'reply'
        || /reply|embed|accessory/i.test(cls)
        || /timestamp/i.test(cls)
        || node.tagName === 'BLOCKQUOTE'
        || node.tagName === 'ARTICLE';
      if (!skip) text += node.textContent;
    }
  }
  return text.trim();
}

setInterval(() => {
  if (_signingKey) attachEnterHook();
  sanitizeReplyPreviews();
}, 1500);

// ─── Render ──────────────────────────────────────────────────────────────────

function renderDecrypted(el, plaintext) {
  el.dataset.ageState = 'ok';
  el.textContent = '';
  const badge = Object.assign(document.createElement('span'), { textContent: '🔒 ' });
  badge.style.userSelect = 'none';
  el.appendChild(badge);
  plaintext.split('\n').forEach((line, i, arr) => {
    el.appendChild(renderMarkdownLine(line));
    if (i < arr.length - 1) el.appendChild(document.createElement('br'));
  });
}

function renderMarkdownLine(text) {
  const wrap = document.createElement('span');
  wrap.style.color = '#889ce6';
  if (/^> /.test(text)) {
    wrap.style.cssText = 'color:#889ce6;border-left:3px solid #5c6aaa;padding-left:8px;display:inline-block;margin:2px 0';
    applyInlineMarkdown(wrap, text.slice(2));
  } else {
    applyInlineMarkdown(wrap, text);
  }
  return wrap;
}

function applyInlineMarkdown(container, text) {
  const tokens = [
    { re: /\*\*(.+?)\*\*/s,  tag: 'strong'  },
    { re: /\*(.+?)\*/s,      tag: 'em'      },
    { re: /__(.+?)__/s,      tag: 'u'       },
    { re: /~~(.+?)~~/s,      tag: 's'       },
    { re: /`([^`]+)`/,       tag: 'code'    },
    { re: /\|\|(.+?)\|\|/s,  tag: 'spoiler' },
  ];

  let remaining = text;
  while (remaining.length > 0) {
    let earliest = null;
    for (const { re, tag } of tokens) {
      const m = re.exec(remaining);
      if (m && (!earliest || m.index < earliest.index))
        earliest = { index: m.index, match: m[0], inner: m[1], tag };
    }

    if (!earliest) { renderWithEmoji(container, remaining); break; }
    if (earliest.index > 0) renderWithEmoji(container, remaining.slice(0, earliest.index));

    if (earliest.tag === 'code') {
      const code = document.createElement('code');
      Object.assign(code.style, {
        background: '#2b2d31', color: '#e3e5e8',
        borderRadius: '3px', padding: '0 4px',
        fontFamily: 'monospace', fontSize: '0.875em',
      });
      code.textContent = earliest.inner;
      container.appendChild(code);
    } else if (earliest.tag === 'spoiler') {
      const sp = document.createElement('span');
      Object.assign(sp.style, {
        background: '#889ce6', color: '#889ce6',
        borderRadius: '3px', padding: '0 2px',
        cursor: 'pointer', userSelect: 'none',
      });
      sp.title = 'Click to reveal';
      applyInlineMarkdown(sp, earliest.inner);
      sp.addEventListener('click', () => { sp.style.color = '#889ce6'; sp.style.background = 'transparent'; });
      container.appendChild(sp);
    } else {
      const el = document.createElement(earliest.tag);
      if (earliest.tag === 'strong') el.style.color = '#889ce6';
      applyInlineMarkdown(el, earliest.inner);
      container.appendChild(el);
    }

    remaining = remaining.slice(earliest.index + earliest.match.length);
  }
}

function renderWithEmoji(container, text) {
  const re = /:([a-zA-Z0-9_+\-]+):/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) container.appendChild(document.createTextNode(text.slice(last, m.index)));
    const name = m[1];
    container.appendChild(document.createTextNode(EMOJI_MAP[name] ?? m[0]));
    last = m.index + m[0].length;
  }
  if (last < text.length) container.appendChild(document.createTextNode(text.slice(last)));
}

function markMessage(el, text, state) {
  if (el.dataset.ageState === 'ok') return;
  el.textContent = text;
  el.style.fontStyle = 'normal';
  el.style.color = ({ ok: '#889ce6', warn: '#fee75c', error: '#ed4245', pending: '#99aab5' })[state] ?? '#99aab5';
}

// ─── Extension messages ───────────────────────────────────────────────────────

const LOCKED_MSG = '🔒 Unlock extension to decrypt.';

function listenForMessages() {
  chrome.runtime.onMessage.addListener(async (msg) => {

    if (msg.type === 'UNLOCK') {
      try {
        const localData = await localGet(['globalOn']);
        _contacts      = msg.contacts || {};
        _selfRecipient = msg.ageRecipient || null;
        _globalOn      = localData.globalOn !== false;
        const pkcs8 = base64UrlToBytes(msg.signingKeyB64);
        _signingKey = await crypto.subtle.importKey(
          'pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']
        );
        // Advance the generation BEFORE touching caches or the DOM so any
        // IIFEs still in-flight from a previous lock cycle see the new
        // generation and no-op rather than writing stale status strings.
        _generation++;
        _inFlight.clear();

        // Surgical cache reset: evict only messages that are NOT yet
        // successfully decrypted.  Messages with state='ok' stay in both
        // caches; processMessageNode will re-render them synchronously from
        // _decryptedCache so they never flash blank.
        // Non-ok entries (pending/warn/error/'') are evicted so they retry.
        for (const msgId of [..._processedIds]) {
          const li = document.getElementById(msgId);
          const el = li && [...li.querySelectorAll('[id^="message-content-"]')]
            .find(e => !e.closest('[class*="repliedText"]') && !e.closest('[class*="replyPreview"]'));
          if (el?.dataset.ageState !== 'ok') {
            _processedIds.delete(msgId);
            _decryptedCache.delete(msgId);
          }
        }

        attachEnterHook();
        // processMessageNode re-renders ok messages from cache synchronously;
        // pending/warn/error messages start fresh decrypt round-trips.
        scanExisting();
        rescanPending();
      } catch (e) {
        console.error('[age] unlock error:', e);
      }
      return;
    }

    if (msg.type === 'CONTACTS_UPDATED') {
      const prevOn   = _globalOn;
      const localData = await localGet(['globalOn']);
      _contacts = msg.contacts || _contacts;
      _globalOn = localData.globalOn !== false;
      if (!_globalOn && prevOn) {
        // Encryption just disabled — mark all ok messages as disabled without
        // clearing the cache, so re-enabling restores them from cache instantly.
        _processedIds.clear();
        _decryptedCache.clear();
        document.querySelectorAll('[id^="message-content-"][data-age-state="ok"]').forEach(el => {
          el.dataset.ageState = '';
          markMessage(el, '🔒 Decryption disabled.', 'pending');
        });
      } else if (_globalOn) {
        // Contacts changed or globalOn just became true.  Evict only non-ok
        // entries so already-decrypted messages stay put; messages that were
        // pending/warn/error (e.g. "No entry") are retried with the updated
        // contacts list.  This also means popup-open no longer flashes every
        // already-decrypted message: the CONTACTS_UPDATED that follows UNLOCK
        // only touches messages that weren't successfully decrypted yet.
        for (const msgId of [..._processedIds]) {
          const li = document.getElementById(msgId);
          const el = li && [...li.querySelectorAll('[id^="message-content-"]')]
            .find(e => !e.closest('[class*="repliedText"]') && !e.closest('[class*="replyPreview"]'));
          if (el?.dataset.ageState !== 'ok') {
            _processedIds.delete(msgId);
            _decryptedCache.delete(msgId);
          }
        }
        if (_signingKey) { scanExisting(); rescanPending(); }
      }
      return;
    }

    if (msg.type === 'RELOCK') {
      _generation++;
      _signingKey    = null;
      _selfRecipient = null;
      _processedIds.clear();
      _decryptedCache.clear();
      _outgoingCache.clear();
      _inFlight.clear();
      detachEnterHook();
      // Reset every message element that has a stashed raw cipher — this
      // covers not only already-decrypted (state='ok') messages but also any
      // that were pending/warn/error, ensuring a full re-scan on next UNLOCK.
      document.querySelectorAll('[id^="message-content-"][data-age-raw]').forEach(el => {
        el.dataset.ageState = '';
        markMessage(el, LOCKED_MSG, 'pending');
      });
    }
  });
}

// ─── SPA navigation ──────────────────────────────────────────────────────────

function startNavObserver() {
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href === lastUrl) return;
    lastUrl = location.href;

    // In-flight guards belong to the previous channel — always clear them so
    // the new channel's messages aren't skipped by a stale _inFlight entry.
    _inFlight.clear();

    // Keep _decryptedCache across navigation: if Discord re-uses the same
    // li.id for the same message (it does — message IDs are stable), we can
    // re-render from cache synchronously without a background round-trip,
    // eliminating the blank-then-decrypt flash on channel re-visit.
    //
    // Only evict processed entries whose DOM node is now gone or not yet 'ok',
    // so that messages which haven't decrypted yet are retried on the new channel.
    for (const msgId of [..._processedIds]) {
      const li = document.getElementById(msgId);
      const el = li && [...li.querySelectorAll('[id^="message-content-"]')]
        .find(e => !e.closest('[class*="repliedText"]') && !e.closest('[class*="replyPreview"]'));
      if (!el || el.dataset.ageState !== 'ok') {
        _processedIds.delete(msgId);
        _decryptedCache.delete(msgId);
      }
    }

    _msgObserver?.disconnect();
    waitForMessageList();
    if (_signingKey) attachEnterHook();

    // Discord's SPA commits the URL change before finishing rendering, so
    // getActiveEntry() called immediately may read a transitional URL.
    // Schedule a rescan after the new channel's list has had time to settle,
    // so messages that landed in warn/error state ("No entry configured") due
    // to that race are retried with the correct URL in place.
    setTimeout(() => { if (_signingKey) rescanPending(); }, 350);
  }).observe(document.body, { subtree: true, childList: true });
}

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  listenForMessages();
  startNavObserver();
  const localData = await localGet(['globalOn']);
  _globalOn = localData.globalOn !== false;
  waitForMessageList();
}

if (document.body) {
  init().catch(e => console.error('[age] init error:', e));
} else {
  document.addEventListener('DOMContentLoaded', () => init().catch(e => console.error('[age] init error:', e)));
}
