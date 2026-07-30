/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// content.js — Agecord
//
// Transport   : message.txt.age uploaded as a Discord file attachment
// File format : [ 1 byte SIG_VERSION ][ SIG_BYTES bytes ML-DSA-87 sig ][ PUBKEY_HINT_LEN bytes sender pubkey hint ][ age ciphertext bytes ]
// Crypto      : age-encryption (MLKEM768X25519 + ChaCha20-Poly1305) + ML-DSA-87 signatures
// Compression : deflate-raw applied to plaintext before encryption
// Sig input   : UTF-8("<channelId>:") + pubKeyHintBytes + raw age ciphertext bytes — contacts & groups
//             : UTF-8("<serverId>:<channelId>:") + pubKeyHintBytes + raw age ciphertext bytes — servers
// Pubkey hint : UTF-8(base64(senderMldsaPubKey) + ":") — PUBKEY_HINT_LEN bytes prepended to age
//               ciphertext in the file and authenticated in the sig input.  Lets the verifier
//               find the matching candidate key via linear scan, avoiding N verify calls.
//
// Decryption path: message.txt.age attachment detected in DOM → iframe CDN fetch
// → file-crypto-worker.js age decrypt → sig verify → render plaintext.
// The age identity never enters the content script's memory directly.
//
// Contacts shape (v2): { [uuid]: { id, type, channelId?, serverId?, username?,
//                                  name?, ageRecipient?, memberIds?, enabled } }
// Contacts and groups looked up by channelId field; servers by serverId.

'use strict';
 
import { init as _rustcryptoInit, ml_dsa87_sign }
  from '../lib/rustcrypto-wasm.min.js';

await _rustcryptoInit();
import { EMOJI_MAP }      from './emoji_map.js';
import { HLJS_LANGUAGES } from './highlight_map.js';
 
// ML-DSA-87 signature size (bytes). Fixed by the standard.
const SIG_BYTES = 4627;

// Sender pubkey hint prepended to the age ciphertext (after the sig).
// Format: UTF-8(base64(mldsaPubKey) + ":") — ML-DSA-87 pubkey = 2592 bytes →
// base64 = ceil(2592/3)*4 = 3456 chars + 1 colon = 3457 bytes.
const PUBKEY_HINT_LEN = 3457;

// Signature format version byte — prepended as the first byte of every .age file.
// Mismatch means the file was produced by an incompatible version; user sees a
// clear notice instead of "Signature invalid".
//
// Version history:
//   0x01 — current: [ 0x01 ][ SIG_BYTES sig ][ PUBKEY_HINT_LEN hint ][ age ciphertext ]
const SIG_VERSION     = 0x01;
const SIG_VERSION_LEN = 1;

// Files larger than this show a confirmation prompt before decryption.
const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024; // 10 MiB
 
// ─── Renderable format allowlists ─────────────────────────────────────────────
// SVG excluded — can execute scripts via object URL in page context.
// BMP/ICO excluded — meaningless attachment types.
// JXL: Chromium 145+ (chrome://flags/#enable-jxl-image-format); Firefox 152+ (image.jxl.enabled).
 
const RENDERABLE_IMAGE = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'apng', 'jxl',
]);
 
const RENDERABLE_VIDEO = new Set([
  'mp4', 'webm', 'mov', 'mkv', 'm4v',
]);
 
const RENDERABLE_AUDIO = new Set([
  'mp3', 'm4a', 'ogg', 'oga', 'wav', 'flac', 'opus', 'aac',
]);
 
// Returns 'image' | 'video' | 'audio' | null. Shared by classifyFile and anonymizeFileName.
function _mediaCategory(ext) {
  if (RENDERABLE_IMAGE.has(ext)) return 'image';
  if (RENDERABLE_VIDEO.has(ext)) return 'video';
  if (RENDERABLE_AUDIO.has(ext)) return 'audio';
  return null;
}

function classifyFile(originalName) {
  const ext = originalName.replace(/\.age$/i, '').split('.').pop().toLowerCase();
  return _mediaCategory(ext) ?? 'download';
}
 
// Returns an anonymized filename preserving only the extension for MIME detection.
// Pattern: <category>.<ext>.age. Already-encrypted files pass through unchanged.
function anonymizeFileName(originalName) {
  if (originalName.endsWith('.age')) return originalName;
  const ext  = originalName.split('.').pop().toLowerCase();
  const base = _mediaCategory(ext) ?? 'file';
  return `${base}.${ext}.age`;
}
 
// ─── Module state ─────────────────────────────────────────────────────────────
 
const _processedIds   = new Set();
// Keyed on stable li.id for fast React re-render.
const _decryptedCache = new Map();
// Deduplicates concurrent decrypt tasks for the same attachment (e.g. flash-jump re-inserts).
const _inFlight = new Map();

// Revoke all blob URLs in _decryptedCache before _decryptedCache.clear().
// Required when switching channels, RELOCK, or disabling the extension, since
// those paths can bypass _evictStaleProcessedIds and leak blobs until tab close.
function _revokeAllCachedMedia() {
  for (const cached of _decryptedCache.values()) {
    if (cached && typeof cached === 'object' && cached.url) URL.revokeObjectURL(cached.url);
  }
}
 
let _mldsaPrivBytes = null; // ML-DSA-87 32-byte seed, held only while unlocked
let _selfRecipient  = null; // own age public key, received at UNLOCK time
let _contacts     = {};
let _contactsLoaded = false; // true once UNLOCK/CONTACTS_UPDATED has actually populated _contacts —
let _globalOn     = true;
let _msgObserver  = null;
let _msgObserver2 = null; // second observer for the thread-panel ol in split view
// Incremented on every RELOCK/UNLOCK so stale async IIFEs silently no-op instead
// of overwriting DOM from a newer cycle.
let _generation   = 0;
 
const sleep    = ms => new Promise(r => setTimeout(r, ms));
const localGet = keys => chrome.storage.local.get(keys);

// ─── Context invalidation ─────────────────────────────────────────────────────
// Set permanently once the extension context is invalidated. All observer/interval
// callbacks check this first to prevent chrome.runtime calls after context death —
// guards against the page-freeze bug (hundreds of synchronous throws/sec locking the JS engine).
let _contextInvalidated = false;

function _signalContextInvalidated() {
  if (_contextInvalidated) return;
  _contextInvalidated = true;

  // Bump _generation so in-flight async tasks silently no-op.
  _generation++;

  try { _msgObserver?.disconnect();  _msgObserver  = null; } catch {}
  try { _msgObserver2?.disconnect(); _msgObserver2 = null; } catch {}

  for (const { timer } of _relTimestampEls.values()) clearTimeout(timer);
  _relTimestampEls.clear();

  try { showAllPlaceholders('locked'); } catch {}

  window.postMessage({ type: 'AGE_CONTEXT_INVALIDATED' }, '*');
}

// Synchronous, zero-IPC context check. Call this before any operation that
// requires a live extension context (encrypt, decrypt, sendMessage).
// Returns false and signals invalidation if the context is already dead.
function isContextValid() {
  if (_contextInvalidated) return false;
  if (!chrome.runtime?.id) { _signalContextInvalidated(); return false; }
  return true;
}

function _isContextInvalidationError(msg) {
  return typeof msg === 'string' && msg.toLowerCase().includes('invalidated');
}

// Safe wrapper around chrome.runtime.sendMessage. On context invalidation, calls
// _signalContextInvalidated() as an error-boundary catch alongside the on-demand
// isContextValid() checks at each crypto entry point.
function bgGetIdentityLine() {
  try {
    return chrome.runtime.sendMessage({ type: 'GET_IDENTITY_LINE' })
      .catch(e => {
        const msg = e?.message ?? String(e);
        if (_isContextInvalidationError(msg)) _signalContextInvalidated();
        return { ok: false, error: msg };
      });
  } catch (e) {
    const msg = e?.message ?? String(e);
    if (_isContextInvalidationError(msg)) _signalContextInvalidated();
    return Promise.resolve({ ok: false, error: msg });
  }
}
 
// ─── DOM helpers ─────────────────────────────────────────────────────────────
 
// Returns the primary composer textbox. Edit-box editors are excluded — main
// composer is inside <form>, edit box is inside <li id^="chat-messages-">.
function getTextbox() {
  const all = document.querySelectorAll('[data-slate-editor="true"]');
  for (const el of all) {
    if (el.closest('form') && !el.closest('li[id^="chat-messages-"]')) return el;
  }
  for (const el of all) {
    if (!el.closest('li[id^="chat-messages-"]')) return el;
  }
  return all[0] ?? null;
}
function getAllMessageLists() { return [...document.querySelectorAll('ol[data-list-id="chat-messages"]')]; }
 
// ─── Route patterns ────────────────────────────────────────────────────────────
// Shared by the getCurrent*Id() helpers and the SPA nav-key derivation below.
// server/channel/thread ids must be numeric, so DM routes (/channels/@me/ID)
// never match the server- or thread-scoped patterns.
const CHANNEL_PATH_PATTERN = new URLPattern({ pathname: '/channels/:guildId/:channelId(\\d+){/*}?' });
const SERVER_CHANNEL_PATH_PATTERN = new URLPattern({ pathname: '/channels/:serverId(\\d+)/:channelId(\\d+){/*}?' });
const THREAD_PATH_PATTERN = new URLPattern({ pathname: '/channels/:serverId(\\d+)/:channelId(\\d+)/threads/:threadId(\\d+){/*}?' });
const CDN_ATTACHMENT_PATH_PATTERN = new URLPattern({ pathname: '/attachments/:channelId(\\d+)/*' });

function getCurrentChannelId() {
  const m = CHANNEL_PATH_PATTERN.exec({ pathname: location.pathname });
  return m ? m.pathname.groups.channelId : null;
}

function getCurrentServerId() {
  const m = SERVER_CHANNEL_PATH_PATTERN.exec({ pathname: location.pathname });
  return m ? m.pathname.groups.serverId : null;
}

// Returns the thread ID from the URL in split-view:
//   /channels/SERVER/CHANNEL/threads/THREAD → THREAD, otherwise null.
function getCurrentThreadId() {
  const m = THREAD_PATH_PATTERN.exec({ pathname: location.pathname });
  return m ? m.pathname.groups.threadId : null;
}

// Extracts the channel ID from a Discord CDN attachment URL.
// Used instead of the page URL because the CDN channel ID always equals the
// channel the sender was in — unaffected by the viewer's navigation (e.g.
// thread single-view where the URL shows THREAD_ID). Both sender and receiver
// derive the sig prefix from this same ground truth without any API call.
function cdnChannelId(url) {
  let m;
  try { m = CDN_ATTACHMENT_PATH_PATTERN.exec(url); } catch { return null; }
  return m ? m.pathname.groups.channelId : null;
}

// Returns the channel ID to bind into the outgoing sig prefix, or null to suppress encryption.
// Channel binding prevents cross-channel replay.
//
// Split-view (/channels/SERVER/CHANNEL/threads/THREAD in URL):
//   Active composer (MAIN vs SECTION) detected via document.activeElement ancestors.
//   SECTION → THREAD_ID  |  MAIN → CHANNEL_ID
//
// Thread/forum first message: thread ID doesn't exist yet, return null (accepted limitation).
function getSendChannelId() {
  const threadId = getCurrentThreadId();

  if (threadId) {
    const active = document.activeElement;
    if (active) {
      let el = active;
      for (let n = 0; n < 20; n++) {
        if (!el.parentElement) break;
        el = el.parentElement;
        if (el.tagName === 'SECTION') return threadId;
        if (el.tagName === 'MAIN')    return getCurrentChannelId();
      }
    }
    return getCurrentChannelId();
  }

  // Forum post creation modal: FORM ancestor, no chat-messages ol → no thread ID yet.
  const active = document.activeElement;
  if (active) {
    let el = active;
    for (let n = 0; n < 20; n++) {
      if (!el.parentElement) break;
      el = el.parentElement;
      if (el.tagName === 'MAIN' || el.tagName === 'SECTION') break;
      if (el.tagName === 'FORM' && !document.querySelector('ol[data-list-id="chat-messages"]')) return null;
    }
  }

  return getCurrentChannelId();
}
 
// Returns { entry, channelId } for the current URL, or null if none matches or
// the entry is disabled. For server entries, entry.serverId is included in the
// sig input to bind to the specific server+channel pair.
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
  return !!(_mldsaPrivBytes && getActiveEntry() && _globalOn);
}
 
// ─── Enter key interception ───────────────────────────────────────────────────
 
// Returns all composer textboxes (1 normally, 2 in split view).
// Editors inside chat-message lis (inline edit boxes) are excluded.
function getTextboxes() {
  const all = [...document.querySelectorAll('[data-slate-editor="true"]')];
  const composers = all.filter(el =>
    el.closest('form') && !el.closest('li[id^="chat-messages-"]'));
  if (composers.length > 0) return composers;
  return all.filter(el => !el.closest('li[id^="chat-messages-"]'));
}

// Closed over `tb` so split-view composers are independently hooked.
function _makeEnterHandler(tb) {
  return (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e.altKey) return;
    if (document.querySelector('[role="listbox"]')) return;
    const focused = document.activeElement;
    if (focused &&
        (focused.closest('[class*="editContainer_"]') ||
         focused.closest('[class*="messageEditorForm_"]'))) return;
    const raw = tb.innerText?.trim() ?? '';
    if (!raw) return;
    if (!isEncryptionActive()) return;

    // getSendChannelId() must be called synchronously — document.activeElement is
    // stable on the keydown stack, before any await.
    if (!getSendChannelId()) return;

    // Suppress Enter after confirming we will encrypt but before the _sending check,
    // so spammed Enter presses during an in-flight cycle never reach Discord.
    e.preventDefault();
    e.stopPropagation();

    if (_sending) return;
    handleEncryptClick();
  };
}

function attachEnterHook() {
  for (const tb of getTextboxes()) {
    if (tb._ageKeyHandler) continue;
    tb._ageKeyHandler = _makeEnterHandler(tb);
    tb.addEventListener('keydown', tb._ageKeyHandler, { capture: true });
  }
}

function detachEnterHook() {
  for (const tb of getTextboxes()) {
    if (tb._ageKeyHandler) {
      tb.removeEventListener('keydown', tb._ageKeyHandler, { capture: true });
      delete tb._ageKeyHandler;
    }
  }
  // Sweep lingering handlers on composers no longer in getTextboxes() (e.g. thread panel closed).
  document.querySelectorAll('[data-slate-editor="true"]').forEach(tb => {
    if (tb._ageKeyHandler) {
      tb.removeEventListener('keydown', tb._ageKeyHandler, { capture: true });
      delete tb._ageKeyHandler;
    }
  });
}
 
// ─── Crypto helpers ───────────────────────────────────────────────────────────
 
// Recipient format: "age1…;mldsa87:<standard-base64>"
function extractMldsaPubBytes(recipientString) {
  const m = recipientString.match(/;mldsa87:([A-Za-z0-9+/]+=*)$/);
  if (!m) return null;
  return fromB64(m[1]);
}

// Sign ageBytes and assemble the on-wire file:
// [ SIG_VERSION ][ SIG_BYTES sig ][ PUBKEY_HINT_LEN hint ][ age ciphertext ]
//
// Shared by the text-send path and the AGE_ENCRYPT_FILE handler.
// channelId must be captured before any await (see getSendChannelId).
// Throws if _selfRecipient is not set.
function buildSignedAgeFile(ageBytes, entry, channelId) {
  if (!_selfRecipient) throw new Error('_selfRecipient not set — extension not fully unlocked');

  // Hint lets the verifier find the matching key via linear scan instead of
  // calling ml_dsa87_verify against every member's key.
  const senderPubKeyB64 = toB64(extractMldsaPubBytes(_selfRecipient));
  const hintBytes = new TextEncoder().encode(senderPubKeyB64 + ':');

  // Colon delimiter is safe — Discord snowflakes are digits only.
  const prefix = (entry.type === 'server')
    ? new TextEncoder().encode(`${entry.serverId}:${channelId}:`)
    : new TextEncoder().encode(`${channelId}:`);

  const sigInput = new Uint8Array(prefix.length + hintBytes.length + ageBytes.length);
  sigInput.set(prefix,    0);
  sigInput.set(hintBytes, prefix.length);
  sigInput.set(ageBytes,  prefix.length + hintBytes.length);

  // ml_dsa87_sign(seed, message) — deterministic from seed.
  const sigBytes = ml_dsa87_sign(_mldsaPrivBytes, sigInput);
  if (sigBytes.length !== SIG_BYTES)
    throw new Error(`Unexpected ML-DSA-87 sig length: ${sigBytes.length}`);

  const fileBytes = new Uint8Array(SIG_VERSION_LEN + SIG_BYTES + hintBytes.length + ageBytes.length);
  fileBytes[0] = SIG_VERSION;
  fileBytes.set(sigBytes,   SIG_VERSION_LEN);
  fileBytes.set(hintBytes,  SIG_VERSION_LEN + SIG_BYTES);
  fileBytes.set(ageBytes,   SIG_VERSION_LEN + SIG_BYTES + hintBytes.length);

  return fileBytes;
}

// Shared by message.txt.age and media paths in processEncryptedAttachment.
// Both derive the prefix from the CDN channel ID (see cdnChannelId).
function buildSigPrefix(entry, channelId) {
  return (entry.type === 'server')
    ? new TextEncoder().encode(`${entry.serverId}:${channelId}:`)
    : new TextEncoder().encode(`${channelId}:`);
}

// Returns candidate ML-DSA-87 public keys (standard-base64) that could have
// signed an incoming .age file — the contact's key plus _selfRecipient for
// contacts, or all member keys for groups/servers.
function buildCandidateKeysB64(entry) {
  let keys;
  if (entry.type === 'contact' || !entry.type) {
    keys = [entry.ageRecipient];
  } else {
    const memberIds = entry.memberIds ?? [];
    keys = memberIds.map(uuid => _contacts[uuid]?.ageRecipient ?? null);
  }
  if (_selfRecipient) keys.push(_selfRecipient);
  return keys
    .filter(Boolean)
    .map(r => { const m = r.match(/;mldsa87:([A-Za-z0-9+/]+=*)$/); return m ? m[1] : null; })
    .filter(Boolean);
}
 
// ─── Base64 helpers ───────────────────────────────────────────────────────────
// Uint8Array.toBase64 / Uint8Array.fromBase64 — baseline since Sep 2025
// (Chrome 128+, Firefox 133+, Safari 18.4+).

const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

// Discord <t:UNIX:STYLE> timestamp rendering. Requires Temporal.
// Supports documented styles (t T d D f F R s S).

const _userLocale     = new Intl.DateTimeFormat().resolvedOptions().locale;
const _userHourCycle  = new Intl.DateTimeFormat().resolvedOptions().hourCycle; // respects OS 24h/12h clock setting

const _TIMESTAMP_OPTS = {
  f: { dateStyle: 'long',  timeStyle: 'short'  },
  F: { dateStyle: 'full',  timeStyle: 'short'  },
  t: { timeStyle: 'short'  },
  T: { timeStyle: 'medium' },
  d: { dateStyle: 'short'  },
  D: { dateStyle: 'long'   },
  s: { dateStyle: 'short', timeStyle: 'short'  },
  S: { dateStyle: 'short', timeStyle: 'medium' },
};

function formatDiscordTimestamp(unixSeconds, style = 'f') {
  const tz      = Temporal.Now.timeZoneId();
  const instant = Temporal.Instant.fromEpochMilliseconds(unixSeconds * 1000);

  if (style === 'R') {
    const diffSecs = (instant.epochMilliseconds - Temporal.Now.instant().epochMilliseconds) / 1000;
    const absSecs  = Math.abs(diffSecs);
    const rtf      = new Intl.RelativeTimeFormat(_userLocale, { numeric: 'auto' });

    if (absSecs < 60)       return rtf.format(Math.round(diffSecs),        'second');
    if (absSecs < 3600)     return rtf.format(Math.round(diffSecs / 60),   'minute');
    if (absSecs < 86400)    return rtf.format(Math.round(diffSecs / 3600), 'hour');
    if (absSecs < 2592000)  return rtf.format(Math.round(diffSecs / 86400),'day');
    if (absSecs < 31536000) return rtf.format(Math.round(diffSecs / 2592000), 'month');
    return rtf.format(Math.round(diffSecs / 31536000), 'year');
  }

  const opts = _TIMESTAMP_OPTS[style] ?? _TIMESTAMP_OPTS.f;
  return new Intl.DateTimeFormat(_userLocale, { timeZone: tz, hourCycle: _userHourCycle, ...opts })
           .format(instant.epochMilliseconds);
}

// Live 'R'-style timestamps. Each element schedules its own update based on
// display granularity; updates stop after 1 day.
const _relTimestampEls = new Map();

function _scheduleRelUpdate(el, unix) {
  // No `isConnected` check here. Initial call may occur before insertion;
  // subsequent timer callbacks check connection state before rescheduling.
  el.textContent = formatDiscordTimestamp(unix, 'R');

  const diffSecs = unix - Temporal.Now.instant().epochMilliseconds / 1000;
  const absSecs  = Math.abs(diffSecs);

  // Schedule just past the Math.round(diffSecs / unit) transition (+1s) to
  // avoid firing exactly on the old value's inclusive boundary.
  const EPSILON_S = 1;
  let delayMs;
  if (absSecs < 60) {
    delayMs = 1000;
  } else if (absSecs < 3600) {
    const unit = 60, half = unit / 2, phase = absSecs % unit;
    delayMs = ((phase < half ? (half - phase) : (unit + half - phase)) + EPSILON_S) * 1000;
  } else if (absSecs < 86400) {
    const unit = 3600, half = unit / 2, phase = absSecs % unit;
    delayMs = ((phase < half ? (half - phase) : (unit + half - phase)) + EPSILON_S) * 1000;
  } else {
    _relTimestampEls.delete(el); return; // ≥1 day: no further scheduled updates
  }

  const timer = setTimeout(() => {
    // Stop the chain once the element has left the live DOM (removed message,
    // virtual-scroll recycling, etc.) instead of ticking a detached node forever.
    if (!el.isConnected) { _relTimestampEls.delete(el); return; }
    _scheduleRelUpdate(el, unix);
  }, delayMs);
  _relTimestampEls.set(el, { unix, timer });
}

// Cancel active schedulers for all <time> elements in `root` (inclusive).
// Call before detaching/replacing any timestamp wrapper to avoid orphaned
// timers retaining detached DOM until their next scheduled tick.
function _clearRelTimestampsIn(root) {
  if (!root) return;
  if (root.tagName === 'TIME') {
    const entry = _relTimestampEls.get(root);
    if (entry) { clearTimeout(entry.timer); _relTimestampEls.delete(root); }
  }
  root.querySelectorAll?.('time').forEach(t => {
    const entry = _relTimestampEls.get(t);
    if (entry) { clearTimeout(entry.timer); _relTimestampEls.delete(t); }
  });
}

// ─── Send ─────────────────────────────────────────────────────────────────────
 
let _sending = false;

// ─── Tray state machine ───────────────────────────────────────────────────────
// Watches for the attachment tray to appear then disappear. Connected on demand;
// disconnected once the tray is gone.
const TRAY_SEL = 'ul[data-list-id="attachments"]';

let _trayState  = 'idle'; // 'idle' | 'appear' | 'gone'
let _trayOnGone = null;

const _trayObserver = new MutationObserver(() => {
  if (_contextInvalidated) {
    _trayObserver.disconnect(); _trayState = 'idle'; return;
  }
  if (_trayState === 'appear' && document.querySelector(TRAY_SEL)) {
    _trayState = 'gone';
  } else if (_trayState === 'gone' && !document.querySelector(TRAY_SEL)) {
    _trayObserver.disconnect();
    _trayState = 'idle';
    const cb = _trayOnGone; _trayOnGone = null; cb?.();
  }
});

// Connect for one send cycle. If the tray is already visible, skip to watching
// for removal. onGone fires exactly once when tray disappears or on timeout.
// DM uploads skip the tray entirely — the 600ms timeout handles that case.
function watchTrayGone(onGone) {
  _trayOnGone = onGone;
  if (document.querySelector(TRAY_SEL)) {
    _trayState = 'gone';
  } else {
    _trayState = 'appear';
    setTimeout(() => {
      if (_trayOnGone === onGone) {
        _trayObserver.disconnect();
        _trayState = 'idle';
        _trayOnGone = null;
        onGone();
      }
    }, 600);
  }
  _trayObserver.observe(document.body, { childList: true, subtree: true });
}
 
// ─── Slate plain-text extraction ──────────────────────────────────────────────
// Must run in page context (upload-interceptor.js): Vencord injects custom emoji
// as <img data-type="emoji"> nodes, which the isolated world can't read via
// memoizedProps. upload-interceptor.js walks the live DOM with a TreeWalker,
// serialising text verbatim and converting Vencord emoji to [name](url) markdown.
// Falls back to innerText if the page context handler is unavailable.
function getSlateTextViaPageContext() {
  return new Promise((resolve) => {
    const nonce = _iframeNextId++;
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_GET_SLATE_TEXT_RESULT') return;
      if (e.data?.nonce !== nonce) return;
      window.removeEventListener('message', handler);
      clearTimeout(timer);
      resolve(e.data.text ?? '');
    };
    window.addEventListener('message', handler);
    window.postMessage({ type: 'AGE_GET_SLATE_TEXT', nonce }, '*');
    const timer = setTimeout(() => {
      window.removeEventListener('message', handler);
      const fallback = getTextbox()?.innerText?.trim() ?? '';
      resolve(fallback);
    }, 500);
  });
}
 
// ─── Slate editor clearing ────────────────────────────────────────────────────
// Must run in page context for two reasons:
//   1. Isolated world gets a copy/proxy of React's heap — changes don't update live state.
//   2. Slate's beforeinput handler rejects synthetic events (isTrusted=false).
// upload-interceptor.js holds the real React editor and calls editor.deleteFragment() directly.
 
async function clearViaPageContext() {
  return new Promise((resolve) => {
    // Nonce ties this listener to this invocation, preventing a stale listener from
    // consuming a later call's result if the 500ms timeout already fired.
    const nonce = _iframeNextId++;
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_CLEAR_TEXTBOX_RESULT') return;
      if (e.data?.nonce !== nonce) return;
      window.removeEventListener('message', handler);
      clearTimeout(timer);
      resolve(e.data);
    };
    window.addEventListener('message', handler);
    window.postMessage({ type: 'AGE_CLEAR_TEXTBOX', nonce }, '*');
    const timer = setTimeout(() => {
      window.removeEventListener('message', handler);
      resolve({ ok: false, error: 'timeout' });
    }, 500);
  });
}
 
async function handleEncryptClick() {
  if (_sending) return;
  if (!isEncryptionActive()) return;
  // Bail immediately if the extension context has been invalidated (update/reload/disable).
  // On-demand check so the send path never attempts chrome.runtime IPC against a dead context.
  if (!isContextValid()) return;
  // Set _sending before the first await so Enter presses during the ~500ms text-extraction
  // window are blocked — otherwise a second Enter would start a duplicate encrypt cycle.
  _sending = true;
  const active = getActiveEntry();
  // Capture synchronously before any await — document.activeElement reflects the composer
  // that triggered the send; it may change after an await.
  const sendChannelId = getSendChannelId();
  if (!sendChannelId) { _sending = false; return; }

  // Cap at 4000 Unicode chars — keeps file sizes predictable and prevents chat flooding.
  const rawPlain = await getSlateTextViaPageContext();
  const plain    = rawPlain ? rawPlain.slice(0, 4000) : rawPlain;
  if (!plain || !active) { _sending = false; return; }

  const { entry } = active;
  try {
    const recipients = [];
    if (entry.type === 'contact' || !entry.type) {
      recipients.push(entry.ageRecipient.split(';')[0]);
    } else {
      for (const memberUUID of (entry.memberIds ?? [])) {
        const member = _contacts[memberUUID];
        if (member?.ageRecipient) recipients.push(member.ageRecipient.split(';')[0]);
      }
    }
    if (_selfRecipient) recipients.push(_selfRecipient.split(';')[0]);

    const ageBuffer = await workerCompressEncrypt(plain, recipients);
    const ageBytes  = new Uint8Array(ageBuffer);
    const fileBytes = buildSignedAgeFile(ageBytes, entry, sendChannelId);
 
    // Sends bytes via postMessage so upload-interceptor calls React's onChange prop
    // directly — bypassing the capture-phase interceptor that fires on DOM 'change' events.
    const uploadResult = await new Promise((resolve) => {
      const handler = (e) => {
        if (e.source !== window || e.data?.type !== 'AGE_DO_UPLOAD_RESULT') return;
        window.removeEventListener('message', handler);
        resolve(e.data);
      };
      window.addEventListener('message', handler);
      window.postMessage(
        { type: 'AGE_DO_UPLOAD', buffer: fileBytes.buffer },
        '*',
        [fileBytes.buffer]
      );
    });
 
    if (!uploadResult.ok) throw new Error('AGE_DO_UPLOAD failed: ' + uploadResult.error);
 
    // Enter hook stays attached: _sending (set before any await) blocks duplicates.
    // Removing it even briefly creates a window where Discord's native handler can
    // fire on a spammed Enter while text is still in the composer.
    const clearResult = await clearViaPageContext();
    if (!clearResult.ok) {
      console.warn('[age] textbox clear failed:', clearResult.error);
    }
 
    // clearOnce is idempotent — whichever fires first (state machine or safety timeout) wins.
    let _attachClearFired = false;
    function clearOnce() {
      if (_attachClearFired) return;
      _attachClearFired = true;
      if (_trayOnGone === clearOnce) _trayOnGone = null;
      window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, '*');
    }

    watchTrayGone(clearOnce);
    setTimeout(clearOnce, 5000); // hard safety: tray appeared but never cleared
 
  } catch (err) {
    console.error('[age] encrypt error:', err);
  } finally {
    _sending = false;
  }
}
 
function _attachToLists(lists, onReady) {
  attachMsgObserver(lists[0], 1);
  if (lists[1]) {
    attachMsgObserver(lists[1], 2);
  } else {
    _msgObserver2?.disconnect();
    _msgObserver2 = null;
  }
  if (!_mldsaPrivBytes || !_globalOn) {
    scanExistingLocked(!_mldsaPrivBytes ? 'locked' : 'disabled');
  }
  scanExisting();
  onReady?.();
}

function waitForMessageList(onReady) {
  const lists = getAllMessageLists();
  if (lists.length > 0) {
    _attachToLists(lists, onReady);
    return;
  }
  // One-shot observer on <main> — fires at the exact millisecond the ol is inserted.
  const root = document.querySelector('main') ?? document.body;
  const obs = new MutationObserver(() => {
    if (_contextInvalidated) { obs.disconnect(); return; }
    const found = getAllMessageLists();
    if (found.length > 0) {
      obs.disconnect();
      _attachToLists(found, onReady);
    }
  });
  obs.observe(root, { childList: true, subtree: true });
}
 
// li id format: "chat-messages-<channelId>-<messageId>"
function _msgIdFromLi(li) {
  const m = li.id.match(/^chat-messages-\d+-(\d+)$/);
  return m ? m[1] : null;
}

// Returns true when a message-content- element belongs to the given li's own message.
// When a reply is expanded, Discord injects a message-content- element with the
// *quoted* message's snowflake — those must not retrigger processing of the enclosing li.
// message-content- id format: "message-content-<messageId>"
function _msgContentBelongsToLi(msgContentEl, li) {
  const liMsgId = _msgIdFromLi(li);
  if (!liMsgId) return true; // can't determine — err on the side of processing
  const m = msgContentEl.id.match(/^message-content-(\d+)$/);
  return m ? m[1] === liMsgId : true;
}

// slot: 1 (primary) or 2 (thread panel in split view)
function attachMsgObserver(list, slot) {
  const observer = new MutationObserver(mutations => {
    if (_contextInvalidated) return;

    // Single revoke/evict pass for this mutation batch; see
    // _evictStaleProcessedIds. Runs before processing additions so removed ids are
    // evicted while recycled ids retain cached URLs.
    _evictStaleProcessedIds();

    let hadNodes = false;
    for (const { addedNodes } of mutations) {
      for (const node of addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        hadNodes = true;

        const lis = new Set();
        if (node.matches?.('li[id^="chat-messages-"]')) {
          lis.add(node);
        } else {
          node.querySelectorAll?.('li[id^="chat-messages-"]').forEach(li => lis.add(li));
          if (node.matches?.('[id^="message-content-"]')) {
            const li = node.closest('li[id^="chat-messages-"]');
            if (li && _msgContentBelongsToLi(node, li)) lis.add(li);
          }
          node.querySelectorAll?.('[id^="message-content-"]').forEach(el => {
            const li = el.closest('li[id^="chat-messages-"]');
            if (li && _msgContentBelongsToLi(el, li)) lis.add(li);
          });
        }

        for (const li of lis) {
          if (_mldsaPrivBytes && _globalOn) {
            processLiFull(li);
          } else {
            showAgePlaceholder(li, !_mldsaPrivBytes ? 'locked' : 'disabled');
          }
        }
      }
    }

    // quotedChatMessage containers are not lis — process only those in the current
    // mutation batch. Full scan happens once in scanExisting().
    if (hadNodes) {
      for (const { addedNodes } of mutations) {
        for (const node of addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;

          if (node.matches?.('[class*="quotedChatMessage__"]')) {
            _processQuotedContainer(node);
            continue;
          }
          node.querySelectorAll?.('[class*="quotedChatMessage__"]')
            .forEach(_processQuotedContainer);
        }
      }
    }
  });
  if (slot === 2) {
    _msgObserver2?.disconnect();
    _msgObserver2 = observer;
  } else {
    _msgObserver?.disconnect();
    _msgObserver = observer;
  }
  observer.observe(list, { childList: true, subtree: true });
}
 
function scanExisting() {
  document.querySelectorAll('li[id^="chat-messages-"]').forEach(processLiFull);
  processQuotedMessages();
}

// Hide a Discord file card (and its mosaic wrapper) so no empty space remains
// where the raw attachment was. Returns the mosaic wrapper (or null) as an
// insertAfter anchor for the caller.
function hideFileCard(fileCard) {
  if (!fileCard) return null;
  fileCard.style.display = 'none';
  const mosaicItem = fileCard.closest('div[class*="mosaicItem_"]');
  if (mosaicItem) mosaicItem.style.display = 'none';
  return mosaicItem ?? null;
}

// Mirrors showAgePlaceholder but for quotedChatMessage containers (no li.id).
function showQuotedPlaceholder(container, reason) {
  const nameLinks = container.querySelectorAll(FILE_LINK_SEL);
  let hasAgeFile = false;
  let lastAnchor = null;
  for (const nameEl of nameLinks) {
    if (!(nameEl.textContent?.trim() ?? '').endsWith('.age')) continue;
    hasAgeFile = true;
    const fileCard = nameEl.closest('div[class*="file_"]');
    const mosaicItem = hideFileCard(fileCard);
    lastAnchor = mosaicItem ?? fileCard ?? lastAnchor;
  }
  if (!hasAgeFile) return;
  container.querySelectorAll('[data-age-msg], [data-age-msg-slot], [data-age-attachment]')
    .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
  const text = reason === 'disabled' ? '🔓 Decryption disabled.' : '🔐 Extension locked.';
  renderDecryptedMessage(container, text, undefined, lastAnchor);
}

function showQuotedPlaceholders(reason) {
  document.querySelectorAll('[class*="quotedChatMessage__"]')
    .forEach(c => showQuotedPlaceholder(c, reason));
}

function scanExistingLocked(reason) {
  document.querySelectorAll('li[id^="chat-messages-"]').forEach(li => showAgePlaceholder(li, reason));
  showQuotedPlaceholders(reason);
}
 
// Re-attaches the Enter hook when Discord recreates the composer without a URL change.
// Replaces a 1500ms polling interval that ran querySelectorAll 40+ times/min.
(function _installComposerObserver() {
  const _composerRoot = document.querySelector('main') ?? document.body;
  new MutationObserver((mutations) => {
    if (_contextInvalidated || !_mldsaPrivBytes) return;
    const editorAdded = mutations.some(({ addedNodes }) =>
      [...addedNodes].some(n =>
        n.nodeType === Node.ELEMENT_NODE &&
        (n.matches?.('[data-slate-editor="true"]') ||
         n.querySelector?.('[data-slate-editor="true"]'))
      )
    );
    if (editorAdded) attachEnterHook();
  }).observe(_composerRoot, { childList: true, subtree: true });
})();
 
// ─── Emoji helpers ────────────────────────────────────────────────────────────
// Discord converts typed/pasted Unicode emoji to :shortcode: in Slate before our
// TreeWalker serialises the message. Nitro custom emoji are serialised as
// [name](cdn-url) by upload-interceptor.js.

const _shortcodeOnlyRe = /^:[a-zA-Z0-9_+\-]+:$/;

// Single source pattern shared by the tokenizer, the
// mdlink branch's group re-exec, and isJumboEmoji's whole-string check, so the
// URL character class can't drift out of sync between them.
const _MDLINK_BODY   = '\\[([^\\]]+)\\]\\((https://[^\\s<>"\'()]+)\\)';
const MDLINK_RE       = new RegExp(_MDLINK_BODY);        // unanchored: find anywhere
const MDLINK_FULL_RE  = new RegExp(`^${_MDLINK_BODY}$`);  // anchored: whole string only

// ── Nitro emoji URL parsing ───────────────────────────────────────────────────
// Format: https://cdn.discordapp.com/emojis/<id>.<ext>?size=<N>[&animated=true]&name=<name>[&lossless=true]
//   • animated=true present → animated; absent → static.
//   • Returns { emojiId, ext, emojiName, isAnimated } or null.
// Security: emojiId → \d+, emojiName → [A-Za-z0-9_], ext validated against RENDERABLE_IMAGE.
//   %00 rejected — URL.parse() doesn't catch percent-encoded null bytes in path/query.
//   protocol/hostname/pathname are all pinned by the URLPattern in one shot;
//   query params still need a real parsed URL, so URL.parse() is used for those.
const NITRO_EMOJI_URL_PATTERN = new URLPattern({
  protocol: 'https',
  hostname: 'cdn.discordapp.com',
  pathname: '/emojis/:emojiId(\\d+).:ext([a-zA-Z0-9]+)',
});
function parseNitroEmojiUrl(url) {
  if (/%00/i.test(url)) return null;
  let match;
  try { match = NITRO_EMOJI_URL_PATTERN.exec(url); } catch { return null; }
  if (!match) return null;
  const { emojiId, ext: rawExt } = match.pathname.groups;
  const ext = rawExt.toLowerCase();
  if (!RENDERABLE_IMAGE.has(ext)) return null;
  const parsed = URL.parse(url);
  if (!parsed) return null;
  const name       = parsed.searchParams.get('name');
  const isAnimated = parsed.searchParams.get('animated') === 'true';
  if (!name || !/^[A-Za-z0-9_]+$/.test(name)) return null;
  return { emojiId, ext, emojiName: name, isAnimated };
}

// ── Sticker URL parsing ───────────────────────────────────────────────────────
// Accepts https://media.discordapp.net/stickers/<id>.<ext>[?<params>].
// name= param decoded if present, null if absent.
// Returns { stickerId, ext, decodedName } or null.
// Security: stickerId → \d+, ext validated against RENDERABLE_IMAGE. %00 rejected.
// decodeURIComponent wrapped in try/catch — can throw on malformed percent-encoding
// independent of URL validity.
const STICKER_URL_PATTERN = new URLPattern({
  protocol: 'https',
  hostname: 'media.discordapp.net',
  pathname: '/stickers/:stickerId(\\d+).:ext([a-zA-Z0-9]+)',
});
function parseStickerUrl(url) {
  if (/%00/i.test(url)) return null;
  let match;
  try { match = STICKER_URL_PATTERN.exec(url); } catch { return null; }
  if (!match) return null;
  const { stickerId, ext: rawExt } = match.pathname.groups;
  const ext = rawExt.toLowerCase();
  if (!RENDERABLE_IMAGE.has(ext)) return null;
  const parsed = URL.parse(url);
  if (!parsed) return null;
  const rawName = parsed.searchParams.get('name');
  if (rawName === null) return { stickerId, ext, decodedName: null };
  try {
    const decodedName = decodeURIComponent(rawName.replace(/\+/g, ' '));
    return { stickerId, ext, decodedName };
  } catch {
    return null;
  }
}

// Returns true when the entire plaintext is a single renderable token:
//   • Nitro emoji:  [name](cdn-emoji-url) where label === name= param
//   • Sticker:      [name](media-sticker-url) where label === decoded name= param
//   • Bare sticker: any media.discordapp.net/stickers/… URL
//   • Shortcode:    :name:
function isJumboEmoji(plaintext) {
  const t = plaintext.trim();
  if (_shortcodeOnlyRe.test(t)) return true;
  const mdm = MDLINK_FULL_RE.exec(t);
  if (mdm) {
    const label = mdm[1];
    const url   = mdm[2];
    const ep = parseNitroEmojiUrl(url);
    if (ep && ep.emojiName === label) return true;
    const sp = parseStickerUrl(url);
    if (sp && sp.decodedName !== null && sp.decodedName === label) return true;
  }
  if (parseStickerUrl(t)) return true;
  return false;
}

// ─── Code block rendering ─────────────────────────────────────────────────────
// HLJS_LANGUAGES used only to decide whether to show a language header —
// no actual syntax highlighting is performed.

const _codeBlockBg      = '#111827';
const _codeBlockBorder  = '#3a4a6b';
const _codeBlockHeader  = '#1c2840';
const _codeBlockText    = '#cdd9f0';
const _codeBlockLangFg  = '#889ce6';

function renderCodeBlock(lang, codeText) {
  const showHeader = lang && HLJS_LANGUAGES.has(lang.toLowerCase());

  const outer = document.createElement('div');
  outer.style.cssText = [
    'display:block',
    `background:${_codeBlockBg}`,
    `border:1px solid ${_codeBlockBorder}`,
    `border-left:3px solid ${_codeBlockLangFg}`,
    'border-radius:8px',
    'overflow:hidden',
    'margin:4px 0',
    'font-family:monospace',
    'font-size:0.875em',
    'position:relative',
  ].join(';');

  const header = document.createElement('div');
  header.style.cssText = [
    `background:${showHeader ? _codeBlockHeader : _codeBlockBg}`,
    showHeader ? `border-bottom:1px solid ${_codeBlockBorder}` : '',
    'padding:4px 8px 4px 12px',
    'display:flex',
    'align-items:center',
    'justify-content:space-between',
    'user-select:none',
    'min-height:28px',
  ].join(';');

  const langLabel = document.createElement('span');
  if (showHeader) {
    langLabel.textContent = lang;
    langLabel.style.cssText = [
      `color:${_codeBlockLangFg}`,
      'font-size:0.875em',
      'letter-spacing:0.04em',
      'font-weight:500',
      'min-width:0',
      'overflow:hidden',
      'text-overflow:ellipsis',
      'white-space:nowrap',
      'margin-right:8px',
    ].join(';');
  }
  header.appendChild(langLabel);

  const copyBtn = document.createElement('button');
  copyBtn.style.cssText = [
    'background:none',
    'border:none',
    'padding:2px',
    'margin:0',
    'cursor:pointer',
    'user-select:none',
    'flex-shrink:0',
    'font-size:1em',
    'line-height:1',
    'opacity:0.65',
    'transition:opacity 120ms',
    'display:inline-flex',
    'align-items:center',
    'justify-content:center',
  ].join(';');
  const _copyIcon = document.createElement('span');
  _copyIcon.style.cssText = 'font-size:.9em;position:relative;top:-.2em;left:-.1em;display:inline-block;transition:opacity 120ms';
  // Two stacked 📄 glyphs create the "copy" visual — front layer via absolute positioning.
  // Built with createElement per the no-innerHTML policy.
  _copyIcon.textContent = '\uD83D\uDCC4';
  const _copyIconFront = document.createElement('span');
  _copyIconFront.style.cssText = 'position:absolute;top:.25em;left:.25em';
  _copyIconFront.textContent = '\uD83D\uDCC4';
  _copyIcon.appendChild(_copyIconFront);
  copyBtn.appendChild(_copyIcon);
  copyBtn.addEventListener('mouseover', () => { copyBtn.style.opacity = '1'; });
  copyBtn.addEventListener('mouseout',  () => { copyBtn.style.opacity = '0.65'; });
  let _copyResetTimer = null;
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(codeText).catch(() => {});
    // Switch to ✔️ — remove the front layer while showing the checkmark.
    _copyIconFront.style.display = 'none';
    _copyIcon.textContent = '\u2714\uFE0F';
    _copyIcon.appendChild(_copyIconFront); // re-attach (textContent detaches child nodes)
    if (_copyResetTimer !== null) clearTimeout(_copyResetTimer);
    _copyResetTimer = setTimeout(() => {
      _copyIcon.textContent = '\uD83D\uDCC4';
      _copyIconFront.style.display = '';
      _copyIcon.appendChild(_copyIconFront);
      _copyResetTimer = null;
    }, 1500);
  });
  header.appendChild(copyBtn);
  outer.appendChild(header);

  const pre = document.createElement('pre');
  pre.style.cssText = [
    'margin:0',
    'padding:10px 12px',
    'overflow-x:auto',
    'white-space:pre',
    `color:${_codeBlockText}`,
  ].join(';');

  const code = document.createElement('code');
  code.textContent = codeText;
  pre.appendChild(code);
  outer.appendChild(pre);
  return outer;
}

// Split plaintext into segments:
//   { type:'text',       lines }
//   { type:'code',       lang, text }
//   { type:'blockquote', lines }   ← leading `>` stripped
//
// Precedence:
//   1. Fenced code blocks (``` … ```) — blockquote detection disabled inside them.
//      Unclosed fence → treated as plain text.
//   2. Blockquote lines — consecutive lines starting with up to three spaces + `>`,
//      followed by a mandatory single space or end-of-line. Adjacent quoted lines
//      become one segment.
//   3. Plain text.
//
// Only ASCII `>` (U+003E) is treated as a blockquote marker. The space after `>`
// is mandatory (rather than optional) so that leading-`>` emoticons like ">:)"
// or ">:(" are left as plain text instead of being parsed as a quote.
function splitBlockSegments(text) {
  const lines    = text.split('\n');
  const segments = [];
  let textLines  = [];
  let quoteLines = [];
  let inCode     = false;
  let codeLang   = '';
  let codeLines  = [];

  function flushText() {
    if (textLines.length) { segments.push({ type: 'text', lines: textLines }); textLines = []; }
  }
  function flushQuote() {
    if (quoteLines.length) { segments.push({ type: 'blockquote', lines: quoteLines }); quoteLines = []; }
  }

  for (const line of lines) {
    if (inCode) {
      if (/^```\s*$/.test(line.trimEnd())) {
        segments.push({ type: 'code', lang: codeLang, text: codeLines.join('\n') });
        inCode    = false;
        codeLang  = '';
        codeLines = [];
      } else {
        codeLines.push(line);
      }
      continue;
    }

    const fenceMatch = /^```([^\s`]*)$/.exec(line.trimEnd());
    if (fenceMatch) {
      flushText();
      flushQuote();
      inCode    = true;
      codeLang  = fenceMatch[1];
      codeLines = [];
      continue;
    }

    // Require a space after `>` (or nothing, for an empty quote line) — CommonMark
    // allows the space to be optional, but that swallows leading-`>` emoticons
    // like ">:)" or ">:(" into a blockquote. Making the space mandatory (when
    // there's trailing content) keeps those as plain text while ">", "> ", and
    // "> text" still all work as quotes.
    const quoteMatch = /^ {0,3}>(?: (.*)|())$/.exec(line);
    if (quoteMatch) {
      flushText();
      quoteLines.push(quoteMatch[1] ?? quoteMatch[2]);
      continue;
    }

    flushQuote();
    textLines.push(line);
  }

  // Unclosed fence — treat accumulated code lines as plain text.
  if (inCode) {
    textLines.push('```' + codeLang, ...codeLines);
  }
  flushQuote();
  if (textLines.length) segments.push({ type: 'text', lines: textLines });
  return segments;
}

// Uses <div> instead of <blockquote>: Discord's stylesheet targets <blockquote>
// with resets (margin, padding, border) that can override inline styles and hide
// the left-border stripe. A plain <div> has no such pre-existing styles.
function renderBlockquote(lines, emojiSize = 22) {
  const bq = document.createElement('div');
  bq.style.cssText = [
    'display:block',
    'margin:4px 0',
    'padding:2px 0 2px 10px',
    `border-left:3px solid ${_codeBlockLangFg}`,  // matches code-block accent stripe
    'opacity:0.9',
    'box-sizing:border-box',
  ].join(';');

  lines.forEach((line, i) => {
    const lineSpan = document.createElement('span');
    lineSpan.style.cssText = 'display:inline-flex;align-items:center;flex-wrap:wrap;gap:0 2px;';
    applyInlineMarkdown(lineSpan, line, emojiSize);
    bq.appendChild(lineSpan);
    if (i < lines.length - 1) bq.appendChild(document.createElement('br'));
  });

  return bq;
}

// For multi-line messages the 🔒 badge is anchored to the left of the entire
// block and vertically centered — it never repeats per-line.
function renderBlockContent(container, text, firstLineIsLock, emojiSize = 22) {
  const segments = splitBlockSegments(text);

  const isMultiLine = firstLineIsLock && (() => {
    let textLineCount = 0;
    for (const seg of segments) {
      if (seg.type === 'code' || seg.type === 'blockquote') return true;
      textLineCount += seg.lines.length;
      if (textLineCount > 1) return true;
    }
    return false;
  })();

  if (!isMultiLine) {
    for (const seg of segments) {
      if (seg.type === 'code') {
        container.appendChild(renderCodeBlock(seg.lang, seg.text));
      } else if (seg.type === 'blockquote') {
        container.appendChild(renderBlockquote(seg.lines, emojiSize));
      } else {
        seg.lines.forEach((line, i) => {
          container.appendChild(renderMarkdownLine(line, firstLineIsLock && i === 0, emojiSize));
          if (i < seg.lines.length - 1) container.appendChild(document.createElement('br'));
        });
      }
    }
    return;
  }

  // Single 🔒 badge centered to the whole body block (matches image/video badge style).
  const outer = document.createElement('span');
  outer.style.cssText = 'display:inline-flex;align-items:center;gap:0 6px;color:#889ce6;';

  const lock = document.createElement('span');
  lock.textContent   = '🔒';
  lock.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;align-self:center;';
  outer.appendChild(lock);

  const body = document.createElement('span');
  body.style.cssText = 'display:inline-block;';
  for (const seg of segments) {
    if (seg.type === 'code') {
      body.appendChild(renderCodeBlock(seg.lang, seg.text));
    } else if (seg.type === 'blockquote') {
      body.appendChild(renderBlockquote(seg.lines, emojiSize));
    } else {
      seg.lines.forEach((line, i) => {
        body.appendChild(renderMarkdownLine(line, false, emojiSize));
        if (i < seg.lines.length - 1) body.appendChild(document.createElement('br'));
      });
    }
  }
  outer.appendChild(body);
  container.appendChild(outer);
}

function renderMarkdownLine(text, lockPrefix, emojiSize = 22) {
  const wrap = document.createElement('span');
  wrap.style.cssText = 'color:#889ce6;display:inline-flex;align-items:center;gap:0 2px;';
  if (lockPrefix) {
    const lock = document.createElement('span');
    lock.textContent = '🔒 ';
    lock.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;';
    wrap.appendChild(lock);
  }
  // flex-wrap on inner span so tokens reflow without pulling the lock badge.
  const content = document.createElement('span');
  content.style.cssText = 'display:inline-flex;align-items:center;flex-wrap:wrap;gap:0 2px;';
  applyInlineMarkdown(content, text, emojiSize);
  wrap.appendChild(content);
  return wrap;
}

// Renders `url` as a clickable link if it passes the safety check, otherwise
// appends `text` as plain text.
function appendLinkOrText(container, url, text) {
  const isSafe = URL.parse(url)?.protocol === 'https:' && !/%00/i.test(url);
  if (isSafe) {
    const a = document.createElement('a');
    a.href   = url;
    a.target = '_blank';
    a.rel    = 'noopener noreferrer';
    a.style.cssText = 'color:#5571de;text-decoration:underline;cursor:pointer;word-break:break-all;';
    a.textContent = text;
    container.appendChild(a);
  } else {
    container.appendChild(document.createTextNode(text));
  }
}

// Anti-phishing: a label that itself looks like a URL misrepresents the real
// destination — true regardless of where the actual href points (even a
// same-origin/trusted host), since the visible text is what the user trusts.
// Delegates to URL.parse() instead of a hand-rolled domain regex: catches
// homograph/IDN look-alike domains that an ASCII-only pattern would silently miss.
function isUrlLikeLabel(label) {
  const trimmed = label.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  const scheme = URL.parse(trimmed)?.protocol;
  if (scheme === 'http:' || scheme === 'https:') return true;
  // Bare domain — prepend a scheme so the parser can
  // validate/normalize the host instead of matching characters by hand.
  return !!URL.parse(`https://${trimmed}`)?.hostname.includes('.');
}

function applyInlineMarkdown(container, text, emojiSize = 22) {
  const tokens = [
    { re: /\*\*(.+?)\*\*/s,  tag: 'strong'  },
    { re: /\*(.+?)\*/s,      tag: 'em'      },
    { re: /__(.+?)__/s,      tag: 'u'       },
    { re: /~~(.+?)~~/s,      tag: 's'       },
    { re: /`([^`]+)`/,       tag: 'code'    },
    { re: /\|\|(.+?)\|\|/s,  tag: 'spoiler' },
    { re: /<t:(\d+)(?::([RfFtTdDSs]))?>/, tag: 'timestamp' },
    // mdlink must come before bare link so the full [label](url) pattern is consumed
    // and the trailing ) is not left as a stray token.
    { re: MDLINK_RE, tag: 'mdlink' },
    // Bare URL: % permitted for percent-encoded slugs (e.g. %C3%A3); scheme-bypass
    // via percent-encoding (javascript%3A) is caught by the post-assignment href check
    // which tests the browser-normalised href. %00 rejected by a separate guard below.
    // One level of parenthesis nesting keeps URLs using them intact.
    { re: /(https:\/\/(?:[^\s<>"'()]*(?:\([^\s<>"'()]*\)[^\s<>"'()]*)*))/,  tag: 'link' },
  ];
 
  let remaining = text;
  while (remaining.length > 0) {
    let earliest = null;
    for (const { re, tag } of tokens) {
      const m = re.exec(remaining);
      if (m && (!earliest || m.index < earliest.index))
        earliest = { index: m.index, match: m[0], inner: m[1], tag };
    }
 
    if (!earliest) { renderWithEmoji(container, remaining, emojiSize); break; }
    if (earliest.index > 0) renderWithEmoji(container, remaining.slice(0, earliest.index), emojiSize);
 
    if (earliest.tag === 'code') {
      const code = document.createElement('code');
      Object.assign(code.style, {
        background: '#1a2236', color: '#889ce6',
        border: '1px solid #2e3d4f',
        borderRadius: '4px', padding: '1px 5px',
        fontFamily: 'monospace', fontSize: '0.875em',
      });
      code.textContent = earliest.inner;
      container.appendChild(code);
    } else if (earliest.tag === 'spoiler') {
      // `inner` holds the real content (links, Nitro/sticker <img>, emoji glyph
      // <span>s) and is made invisible via `visibility: hidden` rather than
      // color-matched or covered by a separately-sized overlay. visibility:hidden
      // hides ANY child regardless of its own color/content type, while still
      // letting it occupy its natural layout box — so the absolutely-positioned
      // cover (sized via inset:0 against that same box) can never be smaller
      // than what it's hiding, unlike a cover sized independently of the content
      // (which clipped tall emoji and wide/wrapped links).
      const sp = document.createElement('span');
      Object.assign(sp.style, {
        position: 'relative', display: 'inline-block',
        borderRadius: '3px', verticalAlign: 'bottom',
      });

      const inner = document.createElement('span');
      Object.assign(inner.style, {
        display: 'inline-flex', alignItems: 'center', flexWrap: 'wrap',
        padding: '0 2px', borderRadius: '3px',
        visibility: 'hidden',
        // Until revealed, content underneath must not be interactive — otherwise
        // the reveal click also lands on a link/emoji and fires it at the same time.
        pointerEvents: 'none',
      });
      applyInlineMarkdown(inner, earliest.inner);
      sp.appendChild(inner);

      const cover = document.createElement('span');
      Object.assign(cover.style, {
        position: 'absolute', inset: '0',
        background: '#889ce6', borderRadius: '3px',
        cursor: 'pointer', userSelect: 'none',
      });
      cover.title = 'Click to reveal';
      sp.appendChild(cover);

      let revealed = false;
      cover.addEventListener('click', (e) => {
        if (revealed) return;
        revealed = true;
        // Swallow this click so it only reveals — it must not also activate a
        // link/emoji now exposed underneath. The next, separate click can.
        e.preventDefault();
        e.stopPropagation();
        cover.remove();
        inner.style.visibility = '';
        inner.style.pointerEvents = '';
      });
      container.appendChild(sp);
    } else if (earliest.tag === 'timestamp') {
      // earliest.inner only carries capture group 1 (the digits); re-extract
      // the optional style letter (group 2) from the full match.
      const styleMatch = /^<t:\d+(?::([RfFtTdDSs]))?>$/.exec(earliest.match);
      const style = styleMatch?.[1] ?? 'f';
      const unix  = parseInt(earliest.inner, 10);

      const formatted = formatDiscordTimestamp(unix, style);
      const fullDate  = formatDiscordTimestamp(unix, 'F');

      const timeEl = document.createElement('time');
      timeEl.textContent = formatted;
      timeEl.title       = fullDate; // hover = full date, regardless of display style
      timeEl.dateTime    = Temporal.Instant.fromEpochMilliseconds(unix * 1000).toString();
      timeEl.style.cssText = [
        'background:#1a2236',
        'border:1px solid #2e3d4f',
        'border-radius:4px',
        'padding:0 4px',
        'color:#889ce6',
        'font-size:0.9em',
        'cursor:default',
        'white-space:nowrap',
      ].join(';');

      if (style === 'R') {
        _scheduleRelUpdate(timeEl, unix);
      }

      container.appendChild(timeEl);
    } else if (earliest.tag === 'mdlink') {
      // Re-exec to extract both capture groups (label + URL); earliest only carries group 1.
      const mdm = MDLINK_RE.exec(earliest.match);
      const label = mdm ? mdm[1] : earliest.inner;
      const url   = mdm ? mdm[2] : '';

      // Nitro emoji: [name](cdn-emoji-url) where label === name= param.
      const emojiParsed = parseNitroEmojiUrl(url);
      if (emojiParsed && emojiParsed.emojiName === label) {
        const safeName     = encodeURIComponent(emojiParsed.emojiName);
        const canonicalUrl = emojiParsed.isAnimated
          ? `https://cdn.discordapp.com/emojis/${emojiParsed.emojiId}.${emojiParsed.ext}?size=${emojiSize}&animated=true&name=${safeName}&lossless=true`
          : `https://cdn.discordapp.com/emojis/${emojiParsed.emojiId}.${emojiParsed.ext}?size=${emojiSize}&name=${safeName}&lossless=true`;
        const px  = `${emojiSize}px`;
        const img = document.createElement('img');
        img.src           = canonicalUrl;
        img.alt           = `:${label}:`;
        img.title         = `:${label}:`;
        img.referrerPolicy = 'no-referrer';
        img.style.cssText = [
          'display:inline-block',
          `width:${px}`,
          `height:${px}`,
          'object-fit:contain',
          'flex-shrink:0',
          'pointer-events:none',
        ].join(';');
        container.appendChild(img);
      } else {
        // Sticker: [label](sticker-url) where label === decoded name= param.
        // Only rendered at emojiSize ≥ 48 (jumbo); otherwise falls back to plain link.
        let stickerHandled = false;
        const stickerParsed = parseStickerUrl(url);
        if (stickerParsed && stickerParsed.decodedName !== null &&
            stickerParsed.decodedName === label) {
          if (emojiSize >= 48) {
            const encodedName = encodeURIComponent(stickerParsed.decodedName).replace(/%20/g, '+');
            const canonicalStickerUrl =
              `https://media.discordapp.net/stickers/${stickerParsed.stickerId}.${stickerParsed.ext}?size=160&name=${encodedName}&lossless=true`;
            const img = document.createElement('img');
            img.src           = canonicalStickerUrl;
            img.alt           = stickerParsed.decodedName;
            img.title         = stickerParsed.decodedName;
            img.referrerPolicy = 'no-referrer';
            img.style.cssText = [
              'display:block',
              'width:160px',
              'height:160px',
              'object-fit:contain',
              'margin:4px 0',
              'pointer-events:none',
            ].join(';');
            container.appendChild(img);
            stickerHandled = true;
          } else if (isUrlLikeLabel(label)) {
            container.appendChild(document.createTextNode(earliest.match));
            stickerHandled = true;
          } else {
            appendLinkOrText(container, url, label);
            stickerHandled = true;
          }
        }

        if (!stickerHandled) {
          // Anti-phishing check takes priority over the safety check below regardless of outcome.
          if (isUrlLikeLabel(label)) {
            container.appendChild(document.createTextNode(earliest.match));
          } else {
            appendLinkOrText(container, url, label);
          }
        }
      }
    } else if (earliest.tag === 'link') {
      const url = earliest.inner;
      // Bare-link regex greedily matches concatenated URLs as one token (e.g.
      // "https://a.comhttps://b.com"). Render as plain text instead.
      // indexOf starts at 1 to skip the leading "https://" of the match itself.
      if (url.indexOf('https://', 1) !== -1) {
        renderWithEmoji(container, url, emojiSize);
        remaining = remaining.slice(earliest.index + earliest.match.length);
        continue;
      }
      // Bare sticker URL: only rendered at emojiSize ≥ 48 (jumbo); otherwise plain link.
      const bareStickerParsed = parseStickerUrl(url);
      if (bareStickerParsed && emojiSize >= 48) {
        const encodedName = bareStickerParsed.decodedName
          ? encodeURIComponent(bareStickerParsed.decodedName).replace(/%20/g, '+')
          : null;
        const canonicalUrl = encodedName
          ? `https://media.discordapp.net/stickers/${bareStickerParsed.stickerId}.${bareStickerParsed.ext}?size=160&name=${encodedName}&lossless=true`
          : `https://media.discordapp.net/stickers/${bareStickerParsed.stickerId}.${bareStickerParsed.ext}?size=160&lossless=true`;
        const altText = bareStickerParsed.decodedName ?? `sticker:${bareStickerParsed.stickerId}`;
        const img = document.createElement('img');
        img.src           = canonicalUrl;
        img.alt           = altText;
        img.title         = altText;
        img.referrerPolicy = 'no-referrer';
        img.style.cssText = [
          'display:block',
          'width:160px',
          'height:160px',
          'object-fit:contain',
          'margin:4px 0',
          'pointer-events:none',
        ].join(';');
        container.appendChild(img);
      } else {
        appendLinkOrText(container, url, url);
      }
    } else {
      const el = document.createElement(earliest.tag);
      // Discord's CSS resets default browser styling on these inline tags (the
      // same reason 'strong' below needs an explicit color), so each formatting
      // tag needs its visual effect set explicitly rather than relying on the
      // browser's UA stylesheet — otherwise e.g. <em> renders with no italics.
      if (earliest.tag === 'strong') el.style.color = '#889ce6';
      if (earliest.tag === 'em')     el.style.fontStyle = 'italic';
      if (earliest.tag === 'u')      el.style.textDecoration = 'underline';
      if (earliest.tag === 's')      el.style.textDecoration = 'line-through';
      applyInlineMarkdown(el, earliest.inner);
      container.appendChild(el);
    }
 
    remaining = remaining.slice(earliest.index + earliest.match.length);
  }
}
 
// Render a text segment that may contain :shortcode: emoji tokens.
// Discord converts Unicode emoji to :shortcode: in the Slate editor, so only
// shortcodes appear in decrypted plaintext. Known shortcodes are looked up in
// EMOJI_MAP and rendered as font-size-controlled <span> elements to respect
// emojiSize (22px inline / 48px jumbo), matching Nitro emoji <img> sizing.
function renderWithEmoji(container, text, emojiSize = 22) {
  const re = /:([a-zA-Z0-9_+\-]+):/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last)
      container.appendChild(document.createTextNode(text.slice(last, m.index)));
    const glyph = EMOJI_MAP[m[1]];
    if (glyph) {
      const sp = document.createElement('span');
      sp.textContent = glyph;
      sp.style.cssText = `font-size:${emojiSize}px;line-height:1;display:inline-block;vertical-align:middle;flex-shrink:0;`;
      container.appendChild(sp);
    } else {
      container.appendChild(document.createTextNode(m[0]));
    }
    last = m.index + m[0].length;
  }
  if (last < text.length)
    container.appendChild(document.createTextNode(text.slice(last)));
}
 
// ─── Fetch iframe ─────────────────────────────────────────────────────────────
// Content scripts cannot fetch cross-origin URLs (CORB/MV3). The background
// service worker can fetch CDN URLs but cannot transfer ArrayBuffers to the
// content script without base64-encoding through JSON IPC — slow for large files.
// An extension-origin iframe CAN fetch cdn.discordapp.com directly (host_permissions)
// and transfer results via postMessage transferables — zero-copy, no base64.
//
// Created lazily on first attachment decrypt, hidden in a shadow root, kept alive
// for the page session, and recreated automatically if Discord removes it.
 
let _fetchIframe   = null;
let _iframeReady   = false;
let _iframeQueue   = [];
const _iframePending = new Map();
let _iframeNextId  = 0;
 
function getFetchIframe() {
  if (_fetchIframe?.isConnected) return _fetchIframe;
 
  _fetchIframe = null;
  _iframeReady = false;
 
  const host = document.createElement('div');
  host.id = 'age-fetch-iframe-host';
  host.style.cssText = 'display:none!important;position:absolute;width:0;height:0;';
  const shadow = host.attachShadow({ mode: 'closed' });
 
  const iframe = document.createElement('iframe');
  // Pass parentOrigin via query instead of ancestorOrigins, which may be
  // redacted by Referrer-Policy and break the READY handshake.
  iframe.src = chrome.runtime.getURL('content/cdn-bridge.html') +
               '?parentOrigin=' + encodeURIComponent(location.origin);
  iframe.style.cssText = 'display:none;';
  // allow-same-origin lets chrome.runtime APIs work inside the iframe (extension origin required).
  iframe.sandbox = 'allow-scripts allow-same-origin';
  shadow.appendChild(iframe);
  document.documentElement.appendChild(host);
 
  _fetchIframe = iframe;
  return iframe;
}
 
function withIframe(fn) {
  getFetchIframe();
  if (_iframeReady) { fn(); return; }
  _iframeQueue.push(fn);
}
 
// Returns Promise<ArrayBuffer> of raw (undecrypted) bytes via zero-copy transfer.
// sig verify + age decrypt happen in file-crypto-worker (VERIFY_DECRYPT or VERIFY_DECRYPT_DECOMPRESS).
function iframePlainFetch(cdnUrl) {
  return new Promise((resolve, reject) => {
    const requestId = String(_iframeNextId++);
    withIframe(() => {
      if (!_fetchIframe?.contentWindow) {
        reject(new Error('fetch iframe unavailable'));
        return;
      }
      const targetWindow = _fetchIframe.contentWindow;
      _iframePending.set(requestId, { resolve, reject, source: targetWindow });
      const iframeOrigin = new URL(chrome.runtime.getURL('')).origin;
      targetWindow.postMessage(
        {
          type:         'AGE_FETCH_RAW',
          requestId,
          cdnUrl,
          parentOrigin: location.origin,
        },
        iframeOrigin
      );
    });
  });
}
 
window.addEventListener('message', (e) => {
  if (e.data?.type === 'AGE_IFRAME_READY') {
    if (!_fetchIframe || e.source !== _fetchIframe.contentWindow) return;
    _iframeReady = true;
    const queue  = _iframeQueue.splice(0);
    for (const fn of queue) fn();
    return;
  }
 
  if (e.data?.type === 'AGE_FETCH_RAW_RESULT') {
    const { requestId, buffer, error } = e.data;
    const entry = _iframePending.get(requestId);
    // Match against the per-request source snapshot so results from an old
    // iframe (replaced mid-flight) are still delivered rather than dropped.
    if (!entry || e.source !== entry.source) return;
    _iframePending.delete(requestId);
    if (error) entry.reject(new Error(error));
    else       entry.resolve(buffer);
  }
});
 
// ─── File crypto Worker pool ──────────────────────────────────────────────────
// Two Workers split by operation type to prevent media ops from starving text
// message decryption. ml_dsa87_verify() is synchronous and CPU-bound — for a
// 50 MB video it blocks the Worker thread for hundreds of ms, queuing all messages
// behind it. Two Workers ensure the text Worker is always free.
//
//   _textWorker  — VERIFY_DECRYPT_DECOMPRESS only (message.txt.age)
//                  never terminated on navigation (kept warm for new channel)
//
//   _mediaWorker — ENCRYPT + VERIFY_DECRYPT (uploads and media attachments)
//                  terminated on channel navigation to unblock large in-flight ops
//
// Media Worker priority queue: ops dispatched smallest-byteLength-first so a
// thumbnail never waits behind a 50 MB video already in the queue.
// byteLength is known before Worker interaction (iframePlainFetch resolves first).
// Queue is unsorted; sorted only on dequeue (depth is typically 1–5 entries).

let _textWorker          = null;
let _textWorkerPending   = new Map();
let _textWorkerNextId    = 0;

let _mediaWorker         = null;
let _mediaWorkerPending  = new Map();
let _mediaWorkerNextId   = 0;

// Each entry: { byteLength, msgArgs, transfers, resolve, reject }
const _mediaQueue     = [];
let   _mediaWorkerBusy = false;

function _spawnWorker(pendingMap) {
  // Content scripts run as the page origin (discord.com), not the extension origin.
  // Chrome forbids constructing a Worker from chrome-extension:// in this context
  // even with web_accessible_resources. Workaround: blob Worker that immediately
  // imports the real module via dynamic import() with its absolute extension URL.
  const workerUrl = chrome.runtime.getURL('content/file-crypto-worker.js');
  const shimSrc   = `import(${JSON.stringify(workerUrl)});`;
  const shimBlob  = new Blob([shimSrc], { type: 'application/javascript' });
  const shimUrl   = URL.createObjectURL(shimBlob);

  const worker = new Worker(shimUrl, { type: 'module' });
  URL.revokeObjectURL(shimUrl);

  worker.onmessage = ({ data }) => {
    const { op, id } = data;
    const entry = pendingMap.get(id);
    if (!entry) return;
    pendingMap.delete(id);
    if (op === 'ENCRYPT_RESULT' ||
        op === 'COMPRESS_ENCRYPT_RESULT' ||
        op === 'VERIFY_DECRYPT_RESULT' ||
        op === 'VERIFY_DECRYPT_DECOMPRESS_RESULT') {
      entry.resolve(data);
    } else {
      entry.reject(new Error(data.error ?? `Worker op failed: ${op}`));
    }
  };

  return worker;
}

function getTextWorker() {
  if (!_textWorker) {
    _textWorker = _spawnWorker(_textWorkerPending);
    _textWorker.onerror = (e) => {
      for (const { reject } of _textWorkerPending.values())
        reject(new Error(`file-crypto-worker (text) crashed: ${e.message}`));
      _textWorkerPending.clear();
      _textWorker = null;
    };
  }
  return _textWorker;
}

function getMediaWorker() {
  if (!_mediaWorker) {
    _mediaWorker = _spawnWorker(_mediaWorkerPending);
    _mediaWorker.onerror = (e) => {
      for (const { reject } of _mediaWorkerPending.values())
        reject(new Error(`file-crypto-worker (media) crashed: ${e.message}`));
      _mediaWorkerPending.clear();
      _mediaWorker = null;
      _mediaWorkerBusy = false;
      _dispatchNextMediaOp();
    };
  }
  return _mediaWorker;
}

// Dequeue and dispatch the smallest-byteLength pending media op.
// Called after each op completes and after enqueue. No-ops when busy or queue empty.
function _dispatchNextMediaOp() {
  if (_mediaWorkerBusy || _mediaQueue.length === 0) return;

  // Linear scan — realistic queue depth is 1–5 entries.
  let minIdx = 0;
  for (let i = 1; i < _mediaQueue.length; i++) {
    if (_mediaQueue[i].byteLength < _mediaQueue[minIdx].byteLength) minIdx = i;
  }
  const { msgArgs, transfers, resolve, reject } = _mediaQueue.splice(minIdx, 1)[0];

  _mediaWorkerBusy = true;
  const id = _mediaWorkerNextId++;
  _mediaWorkerPending.set(id, {
    resolve: (data) => { _mediaWorkerBusy = false; _dispatchNextMediaOp(); resolve(data); },
    reject:  (err)  => { _mediaWorkerBusy = false; _dispatchNextMediaOp(); reject(err);  },
  });
  msgArgs.id = id;
  getMediaWorker().postMessage(msgArgs, transfers);
}

// byteLength used only for priority ordering — not the transfer size.
function _enqueueMediaOp(byteLength, msgArgs, transfers) {
  return new Promise((resolve, reject) => {
    _mediaQueue.push({ byteLength, msgArgs, transfers, resolve, reject });
    _dispatchNextMediaOp();
  });
}

// Terminate the media Worker and reject all pending ops. Called on channel navigation
// so a long-running video verify+decrypt doesn't block new-channel ops.
// Text Worker is kept alive — never the starvation source, stays warm across channels.
// Also drains the priority queue and resets busy flag.
function terminateFileCryptoWorker() {
  if (_mediaWorker) {
    _mediaWorker.terminate();
    _mediaWorker = null;
    for (const { reject } of _mediaWorkerPending.values())
      reject(new Error('Worker terminated — channel navigation'));
    _mediaWorkerPending.clear();
  }
  // Drain the queue — entries may hold transferred (neutered) ArrayBuffers.
  for (const { reject } of _mediaQueue.splice(0))
    reject(new Error('Worker terminated — channel navigation'));
  _mediaWorkerBusy = false;
}
 
// Encrypt plainBuffer with age to the given recipients via the media Worker.
// Returns Promise<ArrayBuffer>. plainBuffer is transferred (neutered after call).
// byteLength captured before transfer since postMessage neuters it immediately.
function workerEncryptFile(plainBuffer, recipients) {
  const byteLength = plainBuffer.byteLength;
  return _enqueueMediaOp(
    byteLength,
    { op: 'ENCRYPT', buffer: plainBuffer, recipients },
    [plainBuffer],
  ).then(data => data.buffer);
}

// Verify ML-DSA-87 signature and age-decrypt a signed media file via the media Worker
// (isolated from text Worker so a large video's synchronous SHAKE-256 never blocks message.txt.age).
// fileBuffer: payload ArrayBuffer with SIG_VERSION byte already stripped ([sig][hint][ciphertext]).
// Transfers fileBuffer — zero-copy. Returns Promise<{ sigValid: bool, buffer?: ArrayBuffer }>.
// Dispatched via media priority queue — smallest byteLength first.
function workerVerifyDecrypt(fileBuffer, identityLine, prefixBytes, candidateKeysB64) {
  const byteLength   = fileBuffer.byteLength;
  const prefixBuffer = prefixBytes.buffer.slice(
    prefixBytes.byteOffset, prefixBytes.byteOffset + prefixBytes.byteLength
  );
  return _enqueueMediaOp(
    byteLength,
    {
      op: 'VERIFY_DECRYPT',
      fileBuffer,
      identityLine,
      candidateKeysB64,
      prefixBuffer,
      sigByteLen:     SIG_BYTES,
      pubkeyHintLen:  PUBKEY_HINT_LEN,
    },
    [fileBuffer],
  );
}

// Compress + age-encrypt a plaintext string via the text Worker (COMPRESS_ENCRYPT op).
// Isolated from the media Worker so a large attachment encrypt never delays sending
// a text message. Returns Promise<ArrayBuffer> of the age ciphertext.
function workerCompressEncrypt(text, recipients) {
  return new Promise((resolve, reject) => {
    const id = _textWorkerNextId++;
    _textWorkerPending.set(id, {
      resolve: (data) => resolve(data.buffer),
      reject,
    });
    getTextWorker().postMessage({ op: 'COMPRESS_ENCRYPT', id, text, recipients });
  });
}

// Fused verify + decrypt + decompress for message.txt.age via the text Worker
// (always isolated from media ops so text messages decrypt immediately).
// fileBuffer: payload ArrayBuffer with SIG_VERSION byte already stripped.
// Transfers fileBuffer — zero-copy. Returns Promise<{ sigValid: bool, plaintext?: string }>.
function workerVerifyDecryptDecompress(fileBuffer, identityLine, prefixBytes, candidateKeysB64) {
  return new Promise((resolve, reject) => {
    const id = _textWorkerNextId++;
    _textWorkerPending.set(id, { resolve, reject });
    getTextWorker().postMessage(
      {
        op: 'VERIFY_DECRYPT_DECOMPRESS',
        id,
        fileBuffer,
        identityLine,
        candidateKeysB64,
        prefixBuffer: prefixBytes.buffer.slice(
          prefixBytes.byteOffset, prefixBytes.byteOffset + prefixBytes.byteLength
        ),
        sigByteLen:    SIG_BYTES,
        pubkeyHintLen: PUBKEY_HINT_LEN,
      },
      [fileBuffer]
    );
  });
}
 
function listenForInterceptorMessages() {
  window.addEventListener('message', async (e) => {
    if (e.source !== window) return;
    if (e.data?.type !== 'AGE_ENCRYPT_FILE') return;
 
    const { requestId, fileName } = e.data;
    const plainBuffer = e.data.buffer;
    // channelId resolved synchronously at event-capture time (before any await) so it
    // always reflects the actual composer — correct even in split-view thread composers
    // where getCurrentChannelId() would return the parent channel.
    // null means channel ID is unreliable (thread-creation, forum modal) — abort.
    const fileChannelId = e.data.channelId ?? null;

    // ACK before any await — upload-interceptor.js uses a 10 s window to detect bridge failures.
    window.postMessage({ type: 'AGE_ENCRYPT_FILE_ACK', requestId }, '*');
 
    try {
      if (fileChannelId === null) {
        throw new Error('Channel ID unavailable — file not encrypted (thread creation or forum modal).');
      }

      // Without this, files in unconfigured channels encrypt only to _selfRecipient — unreadable by recipient.
      const active = getActiveEntry();
      if (!active?.entry) {
        throw new Error(
          'No encrypted contact configured for this channel — file not encrypted.'
        );
      }
 
      const recipients = [];
      const { entry } = active;
      if (entry.type === 'contact' || !entry.type) {
        if (entry.ageRecipient) recipients.push(entry.ageRecipient.split(';')[0]);
      } else {
        for (const memberUUID of (entry.memberIds ?? [])) {
          const member = _contacts[memberUUID];
          if (member?.ageRecipient) recipients.push(member.ageRecipient.split(';')[0]);
        }
      }
      if (_selfRecipient) recipients.push(_selfRecipient.split(';')[0]);
 
      // Secondary guard: entry found but no usable public keys (e.g. group with
      // all members removed, or contact with a malformed ageRecipient).
      if (recipients.length === 0) throw new Error('No recipients — is an encrypted contact selected?');
 
      const encBuffer = await workerEncryptFile(plainBuffer, recipients);
      const ageBytes  = new Uint8Array(encBuffer);

      // Prefix binds the signature to the specific channel (prevents cross-channel replay).
      // fileChannelId from upload-interceptor.js is resolved synchronously at drop time
      // — guaranteed to match the upload channel even in split-view thread composers.
      const fileBytes = buildSignedAgeFile(ageBytes, entry, fileChannelId);

      // Transfer back to page context — zero-copy.
      window.postMessage(
        { type: 'AGE_ENCRYPT_FILE_RESULT', requestId, buffer: fileBytes.buffer, encryptedName: anonymizeFileName(fileName) },
        '*',
        [fileBytes.buffer]
      );
    } catch (err) {
      console.error('[age] AGE_ENCRYPT_FILE error requestId=%s:', requestId, err?.message ?? err);
      window.postMessage(
        { type: 'AGE_ENCRYPT_FILE_RESULT', requestId, error: err.message },
        '*'
      );
    }
  });
}
 
// Tells upload-interceptor.js whether the extension is unlocked and a contact key is available.
// unlocked=true only when both extension is unlocked AND globalOn=true,
// so toggling encryption off propagates as locked=true to the interceptor.
// activeEntry=false in unconfigured channels lets Discord handle uploads normally
// rather than consuming the trusted drop event and silently discarding the file.
function relayInterceptorState(unlocked) {
  const active = (unlocked && _globalOn) ? !!getActiveEntry() : false;
  window.postMessage({ type: 'AGE_INTERCEPTOR_STATE', unlocked: unlocked && _globalOn, activeEntry: active }, '*');
}

// Evict _processedIds/_decryptedCache entries whose message is no longer in
// the DOM. Live entries stay cached to avoid redundant CDN fetches.
// Sole blob URL revoke path. Runs once per message-list mutation batch and
// determines liveness from the current DOM, avoiding races with Discord's
// virtualized list.
// _processedIds keys are "liId\0cdnUrl"; only the liId prefix is a DOM id.
// Quoted messages use liId="" and are matched by quotedChatMessage + CDN URL.
function _evictStaleProcessedIds() {
  for (const attachId of [..._processedIds]) {
    const liId  = attachId.split('\0')[0];
    const url   = attachId.slice(liId.length + 1); // everything after the NUL
    const inDom = liId
      ? !!document.getElementById(liId)
      : [...document.querySelectorAll('[class*="quotedChatMessage__"]')]
          .some(c => c.querySelector(`a[href="${url}"]`));
    if (!inDom) {
      // Media entries are { url, type, originalName } — text entries are a
      // plain plaintext string. Only media entries own a blob: URL to free.
      const cached = _decryptedCache.get(attachId);
      if (cached && typeof cached === 'object' && cached.url) {
        URL.revokeObjectURL(cached.url);
      }
      _processedIds.delete(attachId);
      _decryptedCache.delete(attachId);
    }
  }
}
 
// ─── Extension messages ───────────────────────────────────────────────────────
 
function listenForMessages() {
  chrome.runtime.onMessage.addListener(async (msg) => {
 
    if (msg.type === 'UNLOCK') {
      try {
        const localData = await localGet(['globalOn']);
        _contacts        = msg.contacts || {};
        _contactsLoaded  = true;
        _selfRecipient   = msg.ageRecipient || null;
        _globalOn        = localData.globalOn !== false;
        _mldsaPrivBytes  = fromB64(msg.mldsaSeedB64); // 32-byte ML-DSA-87 seed
        _generation++;
        _inFlight.clear();
        _attachmentInProgress.clear();
 
        // Evict stale entries so they retry; still-present cached entries skip CDN re-fetch.
        _evictStaleProcessedIds();

        if (_globalOn) {
          attachEnterHook();
          relayInterceptorState(true);
          scanExisting();
        } else {
          // Unlocked but globally disabled — replace any stale 'locked' placeholders with 'disabled'.
          relayInterceptorState(false);
          showAllPlaceholders('disabled');
        }
      } catch (e) {
        console.error('[age] unlock error:', e);
      }
      return;
    }
 
    if (msg.type === 'CONTACTS_UPDATED') {
      const prevOn      = _globalOn;
      // Capture before the await — UNLOCK arriving mid-await runs in a separate
      // macrotask and would otherwise have its _contacts overwritten by our stale snapshot.
      const newContacts = msg.contacts;
      const genBefore   = _generation;
      const localData = await localGet(['globalOn']);
      // If _generation changed while awaiting, an UNLOCK already updated all state.
      if (_generation !== genBefore) return;
      _contacts = newContacts || _contacts;
      _contactsLoaded = true;
      _globalOn = localData.globalOn !== false;
      // Always re-relay when contacts change while unlocked: UNLOCK carries an empty
      // contacts object (loadContacts() hasn't finished yet), so CONTACTS_UPDATED is
      // what actually sets activeEntry=true in upload-interceptor.js.
      if (_mldsaPrivBytes && _globalOn) relayInterceptorState(true);
      else if (_globalOn !== prevOn) relayInterceptorState(!!_mldsaPrivBytes);
      if (!_globalOn && prevOn) {
        _generation++;
        _revokeAllCachedMedia();
        _processedIds.clear();
        _decryptedCache.clear();
        _inFlight.clear();
        _attachmentInProgress.clear();
        showAllPlaceholders('disabled');
      } else if (_globalOn) {
        // _evictStaleProcessedIds handles quoted-message entries (liId="") via DOM check.
        _evictStaleProcessedIds();
        if (_mldsaPrivBytes) {
          // Mirrors the UNLOCK handler: a composer that mounted before encryption
          // was enabled never received its keydown listener (attachEnterHook is
          // idempotent, so this is a no-op for composers that already have one).
          attachEnterHook();
          scanExisting();
        }
      }
      return;
    }
 
    if (msg.type === 'RELOCK') {
      _generation++;
      _mldsaPrivBytes = null;
      _selfRecipient  = null;
      _revokeAllCachedMedia();
      _processedIds.clear();
      _decryptedCache.clear();
      _inFlight.clear();
      _attachmentInProgress.clear();
      detachEnterHook();
      relayInterceptorState(false);
      showAllPlaceholders('locked');
    }
  });
}
 
// ─── SPA navigation ──────────────────────────────────────────────────────────
 
// Strips /threads/THREAD_ID suffix so thread open/close doesn't look like a channel change.
// Cache entries are keyed by li.id which encodes channel ID, so only SERVER_ID/CHANNEL_ID matters.
function _navChannelKey(href) {
  let m;
  try { m = SERVER_CHANNEL_PATH_PATTERN.exec(href); } catch { return href; }
  return m ? m.pathname.groups.serverId + '/' + m.pathname.groups.channelId : href;
}

function startNavObserver() {
  let lastUrl     = location.href;
  let lastChanKey = _navChannelKey(location.href);

  // Hook pushState/replaceState instead of a body subtree observer — Discord's SPA
  // router uses History API exclusively and the observer was firing hundreds of times/s.
  function onNav() {
    if (_contextInvalidated) return;
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    const chanKey     = _navChannelKey(location.href);
    const chanChanged = chanKey !== lastChanKey;
    lastChanKey = chanKey;

    _inFlight.clear();
    _attachmentInProgress.clear();

    // Terminate any in-flight media Worker op — a large video decrypt from the
    // previous channel would serialise all new-channel ops behind it otherwise.
    // Bump _generation after termination so the rejection handlers in
    // processEncryptedAttachment discard their results silently rather than
    // rendering an error badge in the wrong channel.
    _generation++;
    terminateFileCryptoWorker();

    if (chanChanged) {
      // li.id encodes channel ID — all existing _processedIds entries are stale on channel change.
      _revokeAllCachedMedia();
      _processedIds.clear();
      _decryptedCache.clear();

      // React replaces the old <ol>, bypassing normal timestamp cleanup. Clear the
      // scheduler map here instead of waiting for disconnected timers to self-expire.
      for (const { timer } of _relTimestampEls.values()) clearTimeout(timer);
      _relTimestampEls.clear();
    }
    // Thread suffix change (panel open/close): keep caches. Main-channel messages
    // are still visible. Thread split-view opens produce two pushState calls
    // (/CHANNEL then /CHANNEL/threads/THREAD); _navChannelKey strips the suffix
    // so the second is same-key — caches preserved, waitForMessageList picks up the new ol.

    _msgObserver?.disconnect();
    _msgObserver2?.disconnect();
    _msgObserver2 = null;
    waitForMessageList();
    if (_mldsaPrivBytes) attachEnterHook();
    relayInterceptorState(!!_mldsaPrivBytes);
  }

  const _origPush    = history.pushState.bind(history);
  const _origReplace = history.replaceState.bind(history);
  history.pushState    = (...a) => { _origPush(...a);    onNav(); };
  history.replaceState = (...a) => { _origReplace(...a); onNav(); };
  window.addEventListener('popstate', onNav);

  // Observer B — Discord often swaps the entire <ol data-list-id="chat-messages">
  // on navigation. The old MutationObserver on the detached <ol> stops firing,
  // so new messages are never processed. Watch <main> (not body) for ol swaps
  // and re-call waitForMessageList when the live set changes.
  const mainEl = document.querySelector('main') ?? document.body;
  let _knownLists = getAllMessageLists();
  new MutationObserver(() => {
    if (_contextInvalidated) return;
    const currentLists = getAllMessageLists();
    const changed = currentLists.length !== _knownLists.length ||
      currentLists.some((l, i) => l !== _knownLists[i]);
    if (changed) {
      _knownLists = currentLists;
      _msgObserver?.disconnect();
      _msgObserver2?.disconnect();
      _msgObserver2 = null;
      waitForMessageList();
    }
  }).observe(mainEl, { childList: true, subtree: true });
}
 
// ─── Encrypted attachment decryption ─────────────────────────────────────────
// Watches for Discord attachment li nodes whose filename ends in '.age',
// fetches the CDN bytes, decrypts via background, and renders inline.
 
// Guards against double-processing the same attachment. Stores attachId → li element.
// Discord's virtual scroller can remove and re-insert a li with the same id/cdnUrl as a
// new DOM object; storing the element reference lets processAttachmentsInLi distinguish
// a stale guard (detached li) from a live concurrent task (same element).
const _attachmentInProgress = new Map(); // attachId → li element
 
// Blob URL revocation is centralized in _evictStaleProcessedIds, the sole
// authority for determining when cached media is safe to release.
 
function renderDecryptedAttachment(liElement, fileCard, url, originalName, type, cdnUrl) {
  const strippedName = originalName.replace(/\.age$/i, '');
 
  const mosaicItem = hideFileCard(fileCard);
 
  // Remove any previous render for this specific attachment only.
  // Key is derived from CDN URL (globally unique per upload) so same-named files
  // in different messages each own their own slot and never clobber each other.
  const cardKey = (() => {
    const s = cdnUrl ?? originalName;
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return 'age-att-' + (h >>> 0).toString(36);
  })();
  liElement.querySelectorAll('[data-age-attachment="' + cardKey + '"]').forEach(el => el.remove());

  // Clear any unslotted [data-age-msg] placeholder (message.txt.age clears at decrypt-start;
  // media files clear here, just before inserting the player/image/download).
  liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
    .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
 
  const wrapper = document.createElement('div');
  wrapper.dataset.ageAttachment = cardKey;
  wrapper.style.cssText = 'margin:4px 0;display:block;';
  
  if (type === 'image') {
    const img = document.createElement('img');
    img.src   = url;
    img.alt   = strippedName;
    img.title = strippedName;
    // width/height:auto preserves intrinsic aspect ratio within the max-width/max-height caps.
    img.style.cssText = [
      'display:block',
      'width:100%',
      'max-width:551px',
      'max-height:344px',
      'height:auto',
      'border-radius:4px',
      'cursor:zoom-in',
    ].join(';');
    img.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href   = url;
      a.target = '_blank';
      a.rel    = 'noopener noreferrer';
      a.click();
    });
    // No contextmenu listener — native right-click menu (save/copy/open image) is preserved.
    const imgWrap = document.createElement('div');
    imgWrap.style.cssText = 'display:flex;align-items:center;gap:6px;';
    const imgLock = document.createElement('span');
    imgLock.textContent   = '🔒';
    imgLock.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;';
    imgWrap.appendChild(imgLock);
    imgWrap.appendChild(img);
    wrapper.style.position = '';
    wrapper.appendChild(imgWrap);

  } else if (type === 'video') {
    const video = document.createElement('video');
    video.src      = url;
    video.controls = true;
    video.autoplay = false;
    // width:100% fills the column; max-width/max-height cap it; aspect-ratio
    // (set below at loadedmetadata) lets the browser reserve height before the
    // first frame paints, avoiding layout shift. height:auto must not be paired
    // with an explicit height px value, which would break the aspect ratio.
    video.style.cssText = [
      'display:block',
      'width:100%',
      'max-width:551px',
      'max-height:350px',
      'height:auto',
      'border-radius:4px',
    ].join(';');
    // No contextmenu listener — native right-click menu (save/copy/PiP) is preserved.
 
    // Set aspect-ratio from intrinsic dimensions once available, so height is
    // reserved before the first frame paints (avoids a visible height jump).
    video.addEventListener('loadedmetadata', () => {
      const w = video.videoWidth;
      const h = video.videoHeight;
      if (w && h) {
        video.style.aspectRatio = w + ' / ' + h;
      }
    }, { once: true });
 
    const videoWrap = document.createElement('div');
    videoWrap.style.cssText = 'display:flex;align-items:center;gap:6px;';
    const videoLock = document.createElement('span');
    videoLock.textContent   = '🔒';
    videoLock.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;';
    videoWrap.appendChild(videoLock);
    videoWrap.appendChild(video);
    wrapper.style.position = '';
    wrapper.appendChild(videoWrap);

  } else if (type === 'audio') {
    const audio    = document.createElement('audio');
    audio.src      = url;
    audio.controls = true;
    audio.autoplay = false;
    audio.style.cssText = 'width:300px;display:block;';

    const audioWrap = document.createElement('div');
    audioWrap.style.cssText = 'display:flex;align-items:center;gap:6px;';
    const audioLock = document.createElement('span');
    audioLock.textContent   = '🔒';
    audioLock.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;';
    audioWrap.appendChild(audioLock);
    audioWrap.appendChild(audio);
    wrapper.style.position = '';
    wrapper.appendChild(audioWrap);
 
  } else {
    // Generic download card (MD3 style). createElement only, never innerHTML.
    // No <iframe>/<embed>/<object> — those would hand the blob to a renderer
    // outside the extension sandbox (e.g. Chrome's PDF viewer).
 
    // CSS variable refs with fallbacks matching popup.css tokens.
    const MD3 = {
      surfaceContainer:     'var(--md-surface-container,      #1c2532)',
      outlineVariant:       'var(--md-outline-variant,        #2e3d4f)',
      onSurface:            'var(--md-on-surface,             #e3e8f0)',
      onSurfaceVariant:     'var(--md-on-surface-variant,     #a8b8cc)',
      primary:              'var(--md-primary,                #64b5f6)',
      shapeSm:              'var(--shape-sm,  12px)',
      shapeFull:            'var(--shape-full, 100px)',
      motionStd:            'var(--motion-standard, cubic-bezier(0.2,0,0,1))',
    };
 
    const card = document.createElement('div');
    card.style.cssText = [
      'display:inline-flex',
      'align-items:center',
      'gap:12px',
      'padding:10px 12px 10px 10px',
      'border-radius:' + MD3.shapeSm,
      'background:' + MD3.surfaceContainer,
      'border:1px solid ' + MD3.outlineVariant,
      'max-width:320px',
      'min-width:180px',
      'box-sizing:border-box',
      'overflow:hidden',
    ].join(';');
 
    // Tonal icon container (MD3 primary tonal style)
    const iconWrap = document.createElement('div');
    iconWrap.style.cssText = [
      'display:flex',
      'align-items:center',
      'justify-content:center',
      'flex-shrink:0',
      'width:36px',
      'height:36px',
      'border-radius:' + MD3.shapeSm,
      'background:color-mix(in srgb, ' + MD3.primary + ' 16%, transparent)',
    ].join(';');
    const lockIcon = document.createElement('span');
    lockIcon.textContent   = '\u{1F512}'; // 🔒
    lockIcon.style.cssText = 'font-size:16px;line-height:1;user-select:none;';
    iconWrap.appendChild(lockIcon);
 
    // Text column: filename + "Encrypted file" label
    const textCol = document.createElement('div');
    textCol.style.cssText = [
      'display:flex',
      'flex-direction:column',
      'gap:1px',
      'flex:1',
      'overflow:hidden',
    ].join(';');
 
    const nameSpan = document.createElement('span');
    nameSpan.textContent   = strippedName;
    nameSpan.title         = strippedName;
    nameSpan.style.cssText = [
      'color:' + MD3.onSurface,
      'font-size:13px',
      'font-weight:500',
      'overflow:hidden',
      'text-overflow:ellipsis',
      'white-space:nowrap',
      'letter-spacing:0.1px',
    ].join(';');
 
    const subSpan = document.createElement('span');
    subSpan.textContent   = 'Encrypted file';
    subSpan.style.cssText = 'color:' + MD3.onSurfaceVariant + ';font-size:11px;';
 
    textCol.appendChild(nameSpan);
    textCol.appendChild(subSpan);
 
    // Save button — MD3 tonal filled style
    const dlBtn = document.createElement('a');
    dlBtn.href      = url;
    dlBtn.download  = strippedName;
    dlBtn.rel       = 'noopener noreferrer';
    dlBtn.textContent = 'Save';
    dlBtn.style.cssText = [
      'display:inline-flex',
      'align-items:center',
      'justify-content:center',
      'flex-shrink:0',
      'padding:0 14px',
      'height:32px',
      'border-radius:' + MD3.shapeFull,
      'background:color-mix(in srgb, ' + MD3.primary + ' 16%, transparent)',
      'color:' + MD3.primary,
      'font-size:13px',
      'font-weight:500',
      'letter-spacing:0.1px',
      'text-decoration:none',
      'white-space:nowrap',
      'transition:background 160ms ' + MD3.motionStd,
    ].join(';');
    dlBtn.addEventListener('mouseover', () => {
      dlBtn.style.background = 'color-mix(in srgb, ' + MD3.primary + ' 24%, transparent)';
    });
    dlBtn.addEventListener('mouseout', () => {
      dlBtn.style.background = 'color-mix(in srgb, ' + MD3.primary + ' 16%, transparent)';
    });
 
    card.appendChild(iconWrap);
    card.appendChild(textCol);
    card.appendChild(dlBtn);
    wrapper.appendChild(card);
  }
 
  // Insert after the hidden mosaic item (or file card) in the DOM flow.
  const insertAfter = mosaicItem ?? fileCard;
  if (insertAfter.parentElement) {
    insertAfter.parentElement.insertBefore(wrapper, insertAfter.nextSibling);
  } else {
    liElement.appendChild(wrapper);
  }
}
 
// Detects a Discord forwarded message via the header's
// data-text-variant="text-sm/semibold" attribute (text content is always
// exactly "Forwarded"; confirmed via DOM probe).
//
// Forwarded .age files can't be verified here: the CDN channel ID reflects
// where the message was originally sent, which may use a different signing
// prefix than the current channel — so we hide the file card and show a
// static notice instead of attempting signature verification.
function isForwardedAttachment(liElement) {
  const el = liElement.querySelector('[data-text-variant="text-sm/semibold"]');
  return el?.textContent.trim() === 'Forwarded';
}

// ─── Large-file confirmation prompt ──────────────────────────────────────────
// Replaces the existing [data-age-msg] spinner with a compact MD3 card.
// Resolves true when the user clicks "Decrypt anyway", or false if
// _generation changes (RELOCK / disable) while the prompt is visible.
function showLargeFilePrompt(liElement, spinnerWrapper, originalName, byteLength, capturedGen) {
  // Always shown in MB; only invoked for files > LARGE_FILE_THRESHOLD.
  const sizeMb = (byteLength / (1024 * 1024)).toFixed(1);
  const displayName = originalName.replace(/\.age$/i, '');

  // Repurpose the spinner wrapper as the prompt card — preserves DOM position.
  const wrapper = spinnerWrapper;
  wrapper.style.cssText = [
    'display:inline-flex',
    'flex-direction:column',
    'gap:0',
    'background:#161b24',
    'border:1px solid #2e3d4f',
    'border-radius:14px',
    'overflow:hidden',
    'max-width:320px',
    'width:100%',
    'box-sizing:border-box',
    'margin:3px 0',
    'font-family:Roboto,system-ui,sans-serif',
  ].join(';');
  // Clear the spinner badge inside.
  wrapper.innerHTML = '';

  // ── Header (darker) — icon + name + size + button ─────────────────────────
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;gap:8px;background:#161b24;padding:10px 12px;';

  const iconWrap = document.createElement('div');
  iconWrap.style.cssText = [
    'width:28px;height:28px',
    'border-radius:6px',
    'background:#1c2532',
    'display:flex;align-items:center;justify-content:center',
    'flex-shrink:0',
    'font-size:14px;line-height:1',
  ].join(';');
  iconWrap.textContent = '🔒';

  const nameMeta = document.createElement('div');
  nameMeta.style.cssText = 'display:flex;flex-direction:column;gap:0;min-width:0;flex:1;';

  const nameEl = document.createElement('span');
  nameEl.style.cssText = 'font-size:12.5px;font-weight:500;color:#e3e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.3;';
  nameEl.textContent = displayName;

  const sizeEl = document.createElement('span');
  sizeEl.style.cssText = 'font-size:11px;color:#a8b8cc;line-height:1.3;';
  sizeEl.textContent = `Encrypted · ${sizeMb} MB`;

  nameMeta.append(nameEl, sizeEl);

  const btn = document.createElement('button');
  btn.style.cssText = [
    'display:inline-flex;align-items:center;justify-content:center',
    'border:none;border-radius:100px',
    'background:#64b5f6;color:#003258',
    'font-family:Roboto,system-ui,sans-serif',
    'font-size:12px;font-weight:500;letter-spacing:0.1px',
    'padding:0 14px;height:28px',
    'cursor:pointer',
    'transition:background 160ms',
    'white-space:nowrap',
    'flex-shrink:0',
  ].join(';');
  btn.textContent = 'Decrypt anyway';
  btn.onmouseenter = () => { btn.style.background = '#90caf9'; };
  btn.onmouseleave = () => { btn.style.background = '#64b5f6'; };

  header.append(iconWrap, nameMeta, btn);

  // ── Warning body — indented to align with the name/size text above ─────────
  // Left offset = icon width (28px) + header gap (8px) = 36px, matching the
  // text column start in the header row.
  const warn = document.createElement('div');
  warn.style.cssText = [
    'background:#1c2532',
    'border-top:1px solid #2e3d4f',
    'padding:8px 12px 9px',
    'padding-left:' + (28 + 8 + 12) + 'px', // icon(28) + gap(8) + card-padding(12)
  ].join(';');

  const warnText = document.createElement('span');
  warnText.style.cssText = 'font-size:11px;color:#a8b8cc;line-height:1.5;';
  warnText.textContent =
    'Decrypting large files keeps the plaintext in memory until this tab is closed. '
    + 'Files over 10 MB may increase memory usage significantly.';

  warn.append(warnText);
  wrapper.append(header, warn);

  // Return a Promise that resolves true on click, false on generation change.
  return new Promise((resolve) => {
    btn.addEventListener('click', () => {
      // Clear the prompt content — renderDecryptedMessage(null) will re-insert
      // the spinner into this same wrapper node immediately after we return.
      wrapper.innerHTML = '';
      wrapper.style.cssText = 'margin:2px 0;overflow-wrap:anywhere;min-width:0;word-break:break-word;';
      resolve(true);
    }, { once: true });

    // Poll _generation — if it changes (RELOCK, UNLOCK, disable) while the
    // prompt is visible, remove the wrapper entirely and resolve false.
    // renderDecryptedMessage / showAllPlaceholders will re-insert the correct
    // badge for the new state via the normal path.
    const poll = setInterval(() => {
      if (_generation !== capturedGen) {
        clearInterval(poll);
        wrapper.remove();
        resolve(false);
      }
    }, 500);

    btn.addEventListener('click', () => clearInterval(poll), { once: true });
  });
}

async function processEncryptedAttachment(liElement, fileCard, cdnUrl, originalName) {
  // isContextValid() calls _signalContextInvalidated() which swaps all placeholders to 'locked'.
  if (!isContextValid()) return;

  // Early exit before async work/forwarding detection so "No entry configured"
  // takes precedence and avoids showing the decrypting placeholder.
  // getActiveEntry() is safe: _contacts is module state updated on
  // UNLOCK/CONTACTS_UPDATED. Callers guarantee _mldsaPrivBytes && _globalOn.
  // Gate on _contactsLoaded rather than _contacts.size() so an empty contact
  // list is treated as loaded.
  if (_contactsLoaded && !getActiveEntry()) {
    _attachmentInProgress.delete(liElement.id + '\0' + cdnUrl);
    const _noEntryMosaicItem = hideFileCard(fileCard);
    renderDecryptedMessage(liElement, '🔑 No entry configured for this channel.', undefined, _noEntryMosaicItem ?? fileCard);
    return;
  }

  // ── Forwarded message guard ───────────────────────────────────────────────────
  // See isForwardedAttachment() — runs after the entry check above so
  // "No entry configured" takes precedence.
  if (isForwardedAttachment(liElement)) {
    _attachmentInProgress.delete(liElement.id + '\0' + cdnUrl);
    const mosaicItem = hideFileCard(fileCard);
    renderDecryptedMessage(liElement, '🚫 Message forwarding is not supported.', null, mosaicItem ?? fileCard);
    return;
  }

  // ── message.txt.age — treat as encrypted text message ────────────────────────
  if (originalName === 'message.txt.age') {
    // Key includes li.id so two message.txt.age files in the same message
    // (same liElement.id, different CDN URLs) get separate cache/in-flight slots.
    const msgId    = liElement.id;
    const attachId = msgId + '\0' + cdnUrl;
 
    // Serve from cache on re-render — no CDN fetch needed.
    if (_processedIds.has(attachId)) {
      const cached = _decryptedCache.get(attachId);
      if (cached) {
        // Skip the DOM write if the rendered wrapper is already present.
        // Re-render only when missing, which happens when the virtual
        // scroller removed and re-inserted the li.
        const alreadyRendered = !!liElement.querySelector(
          `[data-age-msg-slot="${CSS.escape(attachId)}"]`
        );
        if (!alreadyRendered) {
          const mosaicItem = hideFileCard(fileCard);
          renderDecryptedMessage(liElement, cached, attachId, mosaicItem ?? fileCard);
        }
      }
      return;
    }
 
    // ── In-flight deduplication ───────────────────────────────────────────────
    // _inFlight maps attachId → Promise<void> for the running task.
    // Same li, same attachId in flight → MutationObserver fired twice; bail.
    // Different li (flash-jump re-inserted it), same attachId in flight from
    // the old detached task → await that task instead of starting a redundant
    // fetch, then re-enter to hit the cache-hit path above.
    if (_inFlight.has(attachId)) {
      if (_attachmentInProgress.get(attachId) === liElement) return; // same node, already running
      try { await _inFlight.get(attachId); } catch { /* ignore Task A errors */ }
      return processEncryptedAttachment(liElement, fileCard, cdnUrl, originalName);
    }

    // No in-flight task — start one and expose the Promise so a concurrent
    // call for the same attachId can await it.
    let _resolveInflight;
    const inflightPromise = new Promise(res => { _resolveInflight = res; });
    _inFlight.set(attachId, inflightPromise);

    // A placeholder from showAgePlaceholder (locked/disabled) has no slot key —
    // clear it now so it doesn't survive alongside the result.
    liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
      .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
 
    const capturedGeneration = _generation;
    // Hoisted so the catch block can reference it for error rendering.
    let mosaicItem = fileCard.closest('div[class*="mosaicItem_"]');
 
    try {
      if (_generation !== capturedGeneration) return;

      // ── Parallel: resolve identity + fetch CDN bytes ──────────────────
      // Independent operations — run concurrently so CDN latency hides the
      // background IPC round-trip.
      //
      // Both are awaited before reading _contacts / getActiveEntry() so
      // _contacts is stable (post-UNLOCK settlement) before capturedActive
      // is captured.
      const [identResult, fileBuffer] = await Promise.all([
        bgGetIdentityLine(),
        iframePlainFetch(cdnUrl),
      ]);
      if (_generation !== capturedGeneration) return;

      if (!identResult?.ok) {
        // Extension locked mid-flight — retriable once unlocked.
        _attachmentInProgress.delete(attachId);
        mosaicItem = hideFileCard(fileCard);
        renderDecryptedMessage(liElement, '🔐 Extension locked.');
        return;
      }

      // Capture active entry AFTER the awaits — _contacts is now stable.
      const capturedActive = getActiveEntry();

      if (!capturedActive) {
        if (_contactsLoaded) {
        // Contacts loaded but no entry for this channel (including zero configured
        // contacts). Release to avoid stale per-channel map entries; CONTACTS_UPDATED
        // and UNLOCK also clear _attachmentInProgress.
          _attachmentInProgress.delete(attachId);
          mosaicItem = hideFileCard(fileCard);
          renderDecryptedMessage(liElement, '🔑 No entry configured for this channel.');
        } else {
          // Contacts genuinely haven't arrived from the background yet.
          // Release so the next UNLOCK/scanExisting can retry with real contacts.
          _attachmentInProgress.delete(attachId);
        }
        return;
      }

      // Contacts loaded and we have an active entry — show the decrypting
      // placeholder now that we're committed to real work.
      mosaicItem = hideFileCard(fileCard);
      renderDecryptedMessage(liElement, null, attachId, mosaicItem ?? fileCard);

      if (fileBuffer.byteLength < SIG_VERSION_LEN + SIG_BYTES + 1) throw new Error('message.txt.age too short');

      // ── Signature format version check ───────────────────────────────────────
      // Byte 0 is SIG_VERSION, written by every current send path. A mismatch
      // means an older/future extension version produced this file — bail
      // rather than attempt decryption with a byte layout the worker doesn't expect.
      if (new Uint8Array(fileBuffer)[0] !== SIG_VERSION) {
        _attachmentInProgress.delete(attachId);
        renderDecryptedMessage(liElement,
          '🔏 This message was signed using an older signature version.',
          attachId, mosaicItem ?? fileCard);
        return;
      }
      // Strip the version byte — workers expect the buffer starting at the sig.
      const payloadBuffer = fileBuffer.slice(SIG_VERSION_LEN);

      // ── Build sig prefix and candidate key list ─────────────────────
      // Keys are passed to the worker as base64 strings (no ArrayBuffer
      // transfer needed for small key material).
      //
      // Prefix uses the CDN channel ID extracted from cdnUrl, not the page URL —
      // the CDN channel ID is the channel Discord assigned the upload to, which
      // is what the sender used to build the prefix at sign time. This stays
      // correct for thread single-view and for quotedChatMessage containers,
      // where the page URL may not match the channel the message was signed for.
      const { entry } = capturedActive;
      const msgCdnChannelId = cdnChannelId(cdnUrl);
      if (!msgCdnChannelId) throw new Error('Could not extract channel ID from CDN URL');
      const prefix = buildSigPrefix(entry, msgCdnChannelId);
      const candidateKeysB64 = buildCandidateKeysB64(entry);

      if (_generation !== capturedGeneration) return;

      // ── Fused verify + decrypt + decompress in the Worker ────────────
      // Transfers payloadBuffer zero-copy; worker performs ML-DSA-87 verify,
      // age decrypt, and deflate-raw decompress off the main thread, returning
      // { sigValid, plaintext } in one round-trip.
      const workerResult = await workerVerifyDecryptDecompress(
        payloadBuffer, identResult.identityLine, prefix, candidateKeysB64
      );
      // Checked again after the worker await — a RELOCK/UNLOCK during the
      // worker run bumps _generation; writing stale plaintext into the new
      // session's cache would be a cross-session leak.
      if (_generation !== capturedGeneration) return;

      if (!workerResult.sigValid) {
        _attachmentInProgress.delete(attachId);
        renderDecryptedMessage(liElement, '❗ Signature invalid — possible tampering.', attachId, mosaicItem ?? fileCard);
        return;
      }

      const { plaintext } = workerResult;

      _processedIds.add(attachId);
      _decryptedCache.set(attachId, plaintext);
      renderDecryptedMessage(liElement, plaintext, attachId, mosaicItem ?? fileCard);
      _attachmentInProgress.delete(attachId);

    } catch (e) {
      _attachmentInProgress.delete(attachId);
      // A generation change means showAllPlaceholders already wrote the
      // correct status — don't overwrite it with "Couldn't decrypt."
      if (_generation !== capturedGeneration) return;
      // "Couldn't decrypt" is a strong signal that the extension context may
      // have been invalidated mid-flight. Check before rendering the error badge
      // so the page shows the correct 'locked' state instead of a misleading
      // decrypt failure when the real cause is a context loss.
      if (!isContextValid()) return;
      console.info('[age] message.txt.age decrypt skipped (not a valid age file or not encrypted):', e?.message ?? e);
      // Ensure the file card is hidden — if the error was thrown before the
      // normal hide path (e.g. "Extension context invalidated" from
      // bgGetIdentityLine), it would still be visible alongside the error badge.
      const _errMosaicItem = hideFileCard(fileCard);
      renderDecryptedMessage(liElement, "🔓 Couldn't decrypt.", attachId, _errMosaicItem ?? fileCard);
    } finally {
      // Settle the promise — any concurrent awaiter (e.g. a flash-jump
      // re-inserted li) unblocks and re-enters to serve from cache or retry.
      _resolveInflight();
      _inFlight.delete(attachId);
    }
    return;
  }
 
  // ── All other .age files — media/download attachments ────────────────────────
  // Capture generation now — RELOCK or globalOn→false bumps it synchronously,
  // preventing a stale result from re-inserting media after disable/lock.
  const capturedGeneration = _generation;
  // Mirrors the text path's key so _attachmentInProgress stays consistently
  // keyed by (li.id + cdnUrl) across both code paths.
  const attachId = liElement.id + '\0' + cdnUrl;

  // ── Media cache-hit: already decrypted, wrapper still in DOM — skip entirely ──
  // { url, type, originalName } was stored in _decryptedCache on success
  // (below); reuse the blob URL to avoid a redundant fetch + decrypt.
  // If the wrapper isn't in the DOM (virtual scroller recycled the li), fall
  // through and re-render from the cached blob URL without hitting the network.
  if (_processedIds.has(attachId)) {
    const cached = _decryptedCache.get(attachId);
    if (cached?.url) {
      // Recompute the same cardKey used by renderDecryptedAttachment to check
      // whether its wrapper div is still present.
      let _ck = 0;
      for (let i = 0; i < cdnUrl.length; i++) _ck = (Math.imul(31, _ck) + cdnUrl.charCodeAt(i)) | 0;
      const cardKey = 'age-att-' + (_ck >>> 0).toString(36);
      if (liElement.querySelector('[data-age-attachment="' + cardKey + '"]')) {
        return; // wrapper present — nothing to do
      }
      // Wrapper recycled; re-render from cache. _evictStaleProcessedIds revokes and
      // removes cache entries atomically, so a cached entry implies a live blob URL.
      hideFileCard(fileCard);
      renderDecryptedAttachment(liElement, fileCard, cached.url, cached.originalName, cached.type, cdnUrl);
    }
    return;
  }

  // ── In-flight deduplication for media path ───────────────────────────────────
  // Mirrors the text path's _inFlight guard. Without this, the virtual
  // scroller can remount the same media li with a new element reference while
  // the CDN fetch is still running; _attachmentInProgress is identity-based
  // and would see a new li object, allowing a duplicate fetch that stalls the
  // media worker queue.
  if (_inFlight.has(attachId)) {
    if (_attachmentInProgress.get(attachId) === liElement) return; // same node, already running
    // Different node — wait for the in-flight task, then re-enter so the
    // cache-hit path (or a fresh attempt on error) handles the render.
    try { await _inFlight.get(attachId); } catch { /* ignore Task A errors */ }
    return processEncryptedAttachment(liElement, fileCard, cdnUrl, originalName);
  }

  // No in-flight task — start one and expose the Promise so concurrent calls
  // for the same attachId can await it.
  let _resolveMediaInflight;
  const mediaInflightPromise = new Promise(res => { _resolveMediaInflight = res; });
  _inFlight.set(attachId, mediaInflightPromise);

  // ── Show "Decrypting…" placeholder immediately ────────────────────────────────
  // Inserted before the CDN fetch so the user gets instant feedback rather
  // than waiting for the full download (can be several seconds for large
  // files). Identity/entry checks happen after the fetch; on failure the
  // spinner is replaced with the appropriate error badge.
  const _earlyMosaicItem = hideFileCard(fileCard);
  renderDecryptedMessage(liElement, null, undefined, _earlyMosaicItem ?? fileCard);

  try {
    // ── Parallel: resolve identity + fetch CDN bytes ──────────────────────────
    // Independent — run concurrently so CDN latency hides the background IPC
    // round-trip.
    const [identResult, fileBuffer] = await Promise.all([
      bgGetIdentityLine(),
      iframePlainFetch(cdnUrl),
    ]);
    if (_generation !== capturedGeneration) return;

    if (!identResult?.ok) {
      // Extension locked mid-flight — retriable once unlocked.
      _attachmentInProgress.delete(attachId);
      const _lockedMosaicItem = hideFileCard(fileCard);
      renderDecryptedMessage(liElement, '🔐 Extension locked.', undefined, _lockedMosaicItem ?? fileCard);
      return;
    }

    // ── Entry check — required for sig prefix and candidate key list ──────────
    // Capture AFTER the awaits — _contacts is now stable.
    const capturedActive = getActiveEntry();
    if (!capturedActive) {
      _attachmentInProgress.delete(attachId);
      if (_contactsLoaded) {
        // contacts loaded, entry missing (including zero contacts configured) → not a retriable error
        const _noEMosaicItem = hideFileCard(fileCard);
        renderDecryptedMessage(liElement, '🔑 No entry configured for this channel.', undefined, _noEMosaicItem ?? fileCard);
      }
      return;
    }

    if (fileBuffer.byteLength < SIG_VERSION_LEN + SIG_BYTES + 1) throw new Error('media .age file too short');

    // ── Signature format version check ───────────────────────────────────────
    // Checked before the large-file prompt and worker dispatch so old-format
    // files surface a clear notice immediately.
    if (new Uint8Array(fileBuffer)[0] !== SIG_VERSION) {
      _attachmentInProgress.delete(attachId);
      const _verMosaicItem = hideFileCard(fileCard);
      renderDecryptedMessage(liElement,
        '🔏 This file was signed using an older signature version.',
        undefined, _verMosaicItem ?? fileCard);
      return;
    }
    // Strip the version byte — workers expect the buffer starting at the sig.
    const payloadBuffer = fileBuffer.slice(SIG_VERSION_LEN);

    // Alias _earlyMosaicItem for consistent naming in the rest of this function.
    const _attMosaicItem = _earlyMosaicItem;

    // Capture the spinner wrapper so showLargeFilePrompt can mutate it in-place.
    const spinnerWrapper = liElement.querySelector('[data-age-msg]:not([data-age-msg-slot])');

    if (_generation !== capturedGeneration) return;

    // ── Large-file confirmation prompt ────────────────────────────────────────
    // Mutates spinnerWrapper in-place; resolves false and removes the wrapper
    // if _generation changes while the prompt is open.
    if (payloadBuffer.byteLength > LARGE_FILE_THRESHOLD) {
      const confirmed = await showLargeFilePrompt(
        liElement, spinnerWrapper, originalName, payloadBuffer.byteLength, capturedGeneration
      );
      if (!confirmed || _generation !== capturedGeneration) {
        // User didn't confirm or extension state changed — release so a future
        // scanExisting / UNLOCK can retry.
        _attachmentInProgress.delete(attachId);
        return;
      }
      // Re-insert the spinner — prompt cleared the wrapper on resolve.
      renderDecryptedMessage(liElement, null, undefined, _attMosaicItem ?? fileCard);
    }

    if (_generation !== capturedGeneration) return;

    // ── Build sig prefix and candidate key list ───────────────────────────────
    // Uses CDN channel ID from cdnUrl — same ground truth as the sender.
    const { entry } = capturedActive;
    const msgCdnChannelId = cdnChannelId(cdnUrl);
    if (!msgCdnChannelId) throw new Error('Could not extract channel ID from CDN URL');
    const prefix = buildSigPrefix(entry, msgCdnChannelId);
    const candidateKeysB64 = buildCandidateKeysB64(entry);

    if (_generation !== capturedGeneration) return;

    // ── Fused verify + decrypt in the Worker ──────────────────────────────────
    // Transfers payloadBuffer zero-copy; worker performs ML-DSA-87 verify and
    // age decrypt off the main thread, returning { sigValid, buffer }.
    // No decompress step — media files are already compressed by their codecs.
    const workerResult = await workerVerifyDecrypt(
      payloadBuffer, identResult.identityLine, prefix, candidateKeysB64
    );
    // RELOCK/UNLOCK during the worker run bumps _generation.
    if (_generation !== capturedGeneration) return;

    if (!workerResult.sigValid) {
      _attachmentInProgress.delete(attachId);
      liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
        .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
      renderDecryptedMessage(liElement, '❗ Signature invalid — possible tampering.', undefined, _attMosaicItem ?? fileCard);
      return;
    }

    const type     = classifyFile(originalName);
    const ext      = originalName.replace(/\.age$/i, '').split('.').pop().toLowerCase();
    const mimeType = { image: 'image/' + ext, video: 'video/' + ext, audio: 'audio/' + ext }[type]
                  ?? 'application/octet-stream';

    const blob = new Blob([workerResult.buffer], { type: mimeType });
    const url  = URL.createObjectURL(blob);

    renderDecryptedAttachment(liElement, fileCard, url, originalName, type, cdnUrl);
    // Cache blob URL + metadata for re-renders. Released by
    // _evictStaleProcessedIds, the sole blob URL revoke path.
    _processedIds.add(attachId);
    _decryptedCache.set(attachId, { url, type, originalName });
    _attachmentInProgress.delete(attachId);

  } catch (e) {
    _attachmentInProgress.delete(attachId);
    console.error('[age] attachment decrypt error:', e?.message ?? e);
    if (_generation !== capturedGeneration) return;
    if (!isContextValid()) return;
    // Replace the "Decrypting…" placeholder with an error badge.
    liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
      .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
    renderDecryptedMessage(liElement, "🔓 Couldn't decrypt.", undefined, _earlyMosaicItem ?? fileCard);
  } finally {
    // Settle the in-flight promise — any concurrent awaiter unblocks and
    // re-enters to serve from cache or retry on error.
    _resolveMediaInflight();
    _inFlight.delete(attachId);
  }
}
 
// ─── Status badge helpers ─────────────────────────────────────────────────────
// Status messages use two spans: emoji in user-select:none (not clipboard-copied),
// text in a plain selectable span — matching renderMarkdownLine()'s 🔒 prefix.

// All emoji prefixes used by status strings, longest first so multi-codepoint
// sequences match before their base character. Avoids constructing a new
// Intl.Segmenter on every status render.
const _STATUS_EMOJI_PREFIXES = ['🔑', '🔒', '🔓', '🔐', '🚫', '❗', '🔏'];

// Splits a status string (e.g. '🔐 Extension locked.') into its leading emoji
// and the remainder. Uses a prefix scan against _STATUS_EMOJI_PREFIXES rather
// than allocating a new Intl.Segmenter on each call.
function _splitLeadingEmoji(text) {
  for (const emoji of _STATUS_EMOJI_PREFIXES) {
    if (text.startsWith(emoji)) return { emoji, rest: text.slice(emoji.length) };
  }
  // Fallback: shouldn't be reached for known status strings.
  const cp = text.codePointAt(0);
  if (cp === undefined) return { emoji: '', rest: text };
  const len = cp > 0xFFFF ? 2 : 1;
  return { emoji: text.slice(0, len), rest: text.slice(len) };
}

// Builds an inline-flex wrapper with emoji in a user-select:none span and
// the remaining text in a plain selectable span.
function _makeStatusBadge(emoji, rest) {
  const outer = document.createElement('span');
  outer.style.cssText = 'color:#99aab5;font-size:1rem;display:inline-flex;align-items:center;gap:0 2px;';

  const emojiSpan = document.createElement('span');
  emojiSpan.textContent   = emoji;
  emojiSpan.style.cssText = 'font-size:1em;line-height:1;user-select:none;flex-shrink:0;';
  outer.appendChild(emojiSpan);

  if (rest) {
    const textSpan = document.createElement('span');
    textSpan.textContent = rest;
    outer.appendChild(textSpan);
  }

  return outer;
}

// Cached template for the "🔒 Decrypting…" spinner badge.
// cloneNode(true) is cheaper than rebuilding the three-element tree on every
// in-flight attachment. Built lazily so document is guaranteed to be available.
let _decryptingBadgeTemplate = null;
function _makeDecryptingBadge() {
  if (!_decryptingBadgeTemplate)
    _decryptingBadgeTemplate = _makeStatusBadge('🔒', 'Decrypting\u2026');
  return _decryptingBadgeTemplate.cloneNode(true);
}

// Renders a decrypted text message or status badge for one message.txt.age
// attachment within the li (or the whole li for unslotted status badges).
//
// plaintext=null → "Decrypting…" spinner.
//
// slotKey — unique per attachment (liId + NUL + cdnUrl). When supplied, only
//   the wrapper tagged with that slot is replaced, so two concurrent decrypts
//   in the same li don't clobber each other. Omit for whole-li status badges
//   (e.g. "No entry configured") — all [data-age-msg] wrappers are then cleared.
//
// insertAfter — optional DOM node after which the wrapper is inserted, anchoring
//   each slot next to its own hidden file card and preserving visual order.
function renderDecryptedMessage(liElement, plaintext, slotKey, insertAfter) {
  if (slotKey) {
    // Remove this slot's existing wrapper.
    liElement.querySelectorAll('[data-age-msg-slot]').forEach(el => {
      if (el.dataset.ageMsgSlot === slotKey) { _clearRelTimestampsIn(el); el.remove(); }
    });
    // A final result (non-spinner) also clears any unslotted wrapper so two
    // status badges never appear at the same time.
    if (plaintext !== null) {
      liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])').forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
    }
  } else {
    // Unslotted — clear ALL [data-age-msg] wrappers including per-slot ones.
    liElement.querySelectorAll('[data-age-msg]').forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
  }
 
  const wrapper = document.createElement('div');
  wrapper.dataset.ageMsg = '1';
  if (slotKey) wrapper.dataset.ageMsgSlot = slotKey;
  // overflow-wrap:anywhere breaks long unbreakable tokens (URLs, base64, etc.)
  // at any character; min-width:0 lets flex children shrink below content size.
  wrapper.style.cssText  = 'margin:2px 0;overflow-wrap:anywhere;min-width:0;word-break:break-word;';
 
  if (plaintext === null) {
    // cloneNode(true) is cheaper than rebuilding the three-node tree each time.
    wrapper.appendChild(_makeDecryptingBadge());
  } else if (_STATUS_EMOJI_PREFIXES.some(e => plaintext.startsWith(e))) {
    // Emoji gets user-select:none; trailing text remains selectable.
    const seg = _splitLeadingEmoji(plaintext);
    wrapper.appendChild(_makeStatusBadge(seg.emoji, seg.rest));
  } else {
    // Cap at 4 000 characters — senders already enforce this, but guard anyway
    // to prevent runaway DOM growth from crafted messages.
    const displayText = plaintext.length > 4000 ? plaintext.slice(0, 4000) : plaintext;
    const emojiSize = isJumboEmoji(displayText) ? 48 : 22;
    renderBlockContent(wrapper, displayText, true, emojiSize);
  }
 
  // Prefer the explicit insertAfter anchor, then fall back to after
  // message-content- (the li's own text body), then append to the li.
  if (insertAfter?.parentElement) {
    insertAfter.parentElement.insertBefore(wrapper, insertAfter.nextSibling);
  } else {
    // Each <li> has exactly one [id^="message-content-"] for its own text —
    // reply quotes do not get a message-content- id (confirmed via DOM probe).
    const contentEl = liElement.querySelector('[id^="message-content-"]');
    if (contentEl?.parentElement) {
      contentEl.parentElement.insertBefore(wrapper, contentEl.nextSibling);
    } else {
      liElement.appendChild(wrapper);
    }
  }
}
 
// ─── Placeholder display ──────────────────────────────────────────────────────
//
// showAgePlaceholder(li, reason) — hides the Discord file card(s) for every
//   *.age attachment in the li, removes any existing age render wrappers, and
//   inserts a single status badge.
//
// showAllPlaceholders(reason) — sweeps every visible chat li.
//   Called on RELOCK, globalOn→false, and on initial locked load.
//
// reason values:
//   'locked'   → 🔐 Extension locked.
//   'disabled' → 🔓 Decryption disabled.

function showAgePlaceholder(li, reason) {
  const nameLinks = li.querySelectorAll(FILE_LINK_SEL);
  let hasAgeFile = false;
  // Track the last hidden card/mosaic as an insertAfter anchor, placing the
  // status badge right after the hidden file card — matching
  // processEncryptedAttachment behaviour.
  let lastAnchor = null;

  for (const nameEl of nameLinks) {
    if (!(nameEl.textContent?.trim() ?? '').endsWith('.age')) continue;
    hasAgeFile = true;

    const fileCard = nameEl.closest('div[class*="file_"]');
    const mosaicItem = hideFileCard(fileCard);
    // Prefer the outermost hidden node as anchor; fall back to the file card.
    lastAnchor = mosaicItem ?? fileCard ?? lastAnchor;
  }

  if (!hasAgeFile) return;

  li.querySelectorAll('[data-age-msg], [data-age-msg-slot], [data-age-attachment]')
    .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });

  const text = reason === 'disabled'
    ? '🔓 Decryption disabled.'
    : '🔐 Extension locked.';

  renderDecryptedMessage(li, text, undefined, lastAnchor);
}

function showAllPlaceholders(reason) {
  document.querySelectorAll('li[id^="chat-messages-"]')
    .forEach(li => showAgePlaceholder(li, reason));
  showQuotedPlaceholders(reason);
}
 
// Scan a message li for encrypted attachments and process any found.
//
// Filename link selector for Discord CDN attachments.
//
// Confirmed stable via DOM probe:
//   - href prefix is CDN semantics, not a class token.
//   - rel="noreferrer noopener" is set by Discord on all CDN file links.
//   - :not([aria-label]) excludes the "Download" hover button, which shares
//     the same href but carries aria-label="Download".
//
// The file card wrapper is located via closest('div[class*="file_"]') — the
// only stable anchor below message-accessories. closest('[class*="mosaicItem_"]')
// is also kept. Both are isolated here so a single-line fix suffices if
// Discord renames them.
const FILE_LINK_SEL =
  'a[href^="https://cdn.discordapp.com/attachments/"]' +
  '[rel="noreferrer noopener"]:not([aria-label])';

function processAttachmentsInLi(li) {
  const nameLinks = li.querySelectorAll(FILE_LINK_SEL);
  for (const nameEl of nameLinks) {
    const rawName = nameEl.textContent?.trim() ?? '';
    if (!rawName.endsWith('.age')) continue;

    const cdnUrl  = nameEl.href;
    if (!cdnUrl) continue;

    const fileCard = nameEl.closest('div[class*="file_"]');
    if (!fileCard) continue;

    // Guard keyed by (li.id + cdnUrl), not cdnUrl alone.
    // cdnUrl-only keying caused a bug: when Discord's virtual scroller removes
    // and re-inserts a li (e.g. after a flash-jump reply click), the new li
    // element is a distinct DOM node with the same id and cdnUrl. A cdnUrl-only
    // guard would block it if the prior async task's closure still held the old
    // detached fileCard. Per-(li.id + cdnUrl) keying gives each li/cdnUrl
    // combination its own in-progress slot; _inFlight uses the same key.
    const attachId = li.id + '\0' + cdnUrl;
    // If the stored element is the exact same DOM node, a task is in flight —
    // skip. A different object means Discord re-inserted the li (flash-jump);
    // the guard is stale — bypass so the new li is processed.
    const inProgressLi = _attachmentInProgress.get(attachId);
    if (inProgressLi === li) continue;
    _attachmentInProgress.set(attachId, li);

    processEncryptedAttachment(li, fileCard, cdnUrl, rawName);
  }
}

// Processes a single quotedChatMessage container from the hot MutationObserver
// path in attachMsgObserver(). Mirrors the per-container loop in
// processQuotedMessages() for only the containers in the current mutation batch.
function _processQuotedContainer(container) {
  if (_mldsaPrivBytes && _globalOn) {
    const nameLinks = container.querySelectorAll(FILE_LINK_SEL);
    for (const nameEl of nameLinks) {
      const rawName = nameEl.textContent?.trim() ?? '';
      if (!rawName.endsWith('.age')) continue;
      const cdnUrl = nameEl.href;
      if (!cdnUrl) continue;
      const fileCard = nameEl.closest('div[class*="file_"]');
      if (!fileCard) continue;
      const attachId = '\0' + cdnUrl;
      if (_processedIds.has(attachId)) continue;
      if (_inFlight.has(attachId)) continue;
      if (_attachmentInProgress.get(attachId) === container) continue;
      _attachmentInProgress.set(attachId, container);
      processEncryptedAttachment(container, fileCard, cdnUrl, rawName);
    }
  } else {
    showQuotedPlaceholder(container, !_mldsaPrivBytes ? 'locked' : 'disabled');
  }
}

// Scans quotedChatMessage containers for encrypted attachments.
//
// Thread origin messages are rendered inside div[class*="quotedChatMessage__"]
// rather than li[id^="chat-messages-"], so processAttachmentsInLi() never
// reaches them.
//
// The sig prefix is derived from the CDN URL (same as all other messages), so
// both parent-channel and thread-posted origin messages verify correctly without
// special-casing.
//
// The container has no stable li.id, so we use a synthetic key:
// "\0<cdnUrl>" — globally unique per attachment URL.
function processQuotedMessages() {
  if (!_mldsaPrivBytes || !_globalOn) return;
  const containers = document.querySelectorAll('[class*="quotedChatMessage__"]');
  for (const container of containers) {
    const nameLinks = container.querySelectorAll(FILE_LINK_SEL);
    for (const nameEl of nameLinks) {
      const rawName = nameEl.textContent?.trim() ?? '';
      if (!rawName.endsWith('.age')) continue;
      const cdnUrl = nameEl.href;
      if (!cdnUrl) continue;
      const fileCard = nameEl.closest('div[class*="file_"]');
      if (!fileCard) continue;
      // processEncryptedAttachment builds attachId as liElement.id + "\0" + cdnUrl.
      // quotedChatMessage containers have no id, so liElement.id is ""; key
      // becomes "\0" + cdnUrl.
      const attachId = '\0' + cdnUrl;
      if (_processedIds.has(attachId)) continue;
      // _inFlight is keyed by string so it stays valid even when Discord remounts
      // the quotedChatMessage container as a new DOM object mid-reconciliation —
      // the case that caused double "Decrypting… → Decrypted" renders.
      // _attachmentInProgress is element-identity-based and misses the remounted node.
      if (_inFlight.has(attachId)) continue;
      if (_attachmentInProgress.get(attachId) === container) continue;
      _attachmentInProgress.set(attachId, container);
      processEncryptedAttachment(container, fileCard, cdnUrl, rawName);
    }
  }
}
 
// Called from attachMsgObserver and scanExisting.
function processLiFull(li) {
  if (_mldsaPrivBytes && _globalOn) processAttachmentsInLi(li);
}
 
// ─── Init ────────────────────────────────────────────────────────────────────
 
async function init() {
  listenForMessages();
  listenForInterceptorMessages();
  startNavObserver();
  const localData = await localGet(['globalOn']);
  _globalOn = localData.globalOn !== false;
  waitForMessageList();
  relayInterceptorState(false);
  // Warm up iframe and workers before any attachment is found so the first
  // decrypt pays no cold-start penalty.
  getFetchIframe();
  getTextWorker();   // never terminated
  getMediaWorker();  // terminated on nav, recreated lazily
}
 
if (document.body) {
  init().catch(e => console.error('[age] init error:', e));
} else {
  document.addEventListener('DOMContentLoaded', () => init().catch(e => console.error('[age] init error:', e)));
}
