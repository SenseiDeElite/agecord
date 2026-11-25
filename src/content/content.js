/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// content.js — Agecord

// Transport: message.txt.age Discord attachments
// Format: [sig version][ML-DSA-87 signature][pubkey hint][age ciphertext]
// Crypto: age (MLKEM768X25519 + ChaCha20-Poly1305), ML-DSA-87, deflate-raw
// Signature input: channel/server context + pubkey hint + age ciphertext.
// Pubkey hint identifies the ML-DSA key before verification.

// Decryption: attachment → CDN bridge → file-crypto-worker.js → render.
// Workers handle age crypto, compression, and ML-DSA-87 signing/verification;
// content.js retains two secrets: cachedIdentityLine (immutable JS string) and
// mldsaSeedBytes (zeroed on lock/session replacement). Both only resend UNLOCK
// to workers; payload.mldsaSeedB64 is also immutable and cannot be zeroed.

// Contacts (v2): keyed by UUID; resolved by channelId or serverId.

// Everything below runs inside one function scope so that
// its top-level declarations stay out of the isolated world's global scope.
(() => {
'use strict';

// Lookup tables provided by emoji_map.js and highlight_map.js, which the manifests
// list before this file. Taken once and removed from the global object.
const EMOJI_MAP       = globalThis.__AGECORD_EMOJI_MAP__;
const HLJS_LANGUAGES  = globalThis.__AGECORD_HLJS_LANGUAGES__;
delete globalThis.__AGECORD_EMOJI_MAP__;
delete globalThis.__AGECORD_HLJS_LANGUAGES__;
if (!EMOJI_MAP || !HLJS_LANGUAGES) {
  throw new Error('[age] emoji_map.js / highlight_map.js must load before content.js');
}

// ML-DSA-87 signature size (bytes). Fixed by the standard.
const SIG_BYTES = 4627;

// Sender pubkey hint prepended to the age ciphertext (after the sig).
// Format: UTF-8(base64(mldsaPubKey) + ":") — ML-DSA-87 pubkey = 2592 bytes →
// base64 = ceil(2592/3)*4 = 3456 chars + 1 colon = 3457 bytes.
const PUBKEY_HINT_LEN = 3457;

// Signature format version byte — prepended as the first byte of every .age file.
// A mismatch is rejected by the bridge (cdn-bridge.js checkHeader, KEEP IN SYNC) before the
// bytes reach this script.

// Version history:
//   0x01 — current: [ 0x01 ][ SIG_BYTES sig ][ PUBKEY_HINT_LEN hint ][ age ciphertext ]
const SIG_VERSION     = 0x01;
const SIG_VERSION_LEN = 1;

// Layout parameters sent with every worker sign/verify message; the worker takes
// the layout from the message rather than keeping its own copy of these constants.
const SIG_LAYOUT = { sigByteLen: SIG_BYTES, pubkeyHintLen: PUBKEY_HINT_LEN };

// Files larger than this show a confirmation prompt before decryption.
const LARGE_FILE_THRESHOLD = 20 * 1024 * 1024; // 20 MiB

// ─── Renderable format allowlists ─────────────────────────────────────────────

// SVG excluded — can execute scripts via object URL in page context.
// BMP/ICO excluded — meaningless attachment types.

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

// Strips the trailing .age extension from a filename, if present.
function stripAgeSuffix(name) {
  return name.replace(/\.age$/i, '');
}

function classifyFile(originalName) {
  const ext = stripAgeSuffix(originalName).split('.').pop().toLowerCase();
  return _mediaCategory(ext) ?? 'download';
}

// Returns <category>.<ext>.age or file.age; preserves recognized extensions for MIME detection.
// Encrypted files pass through unchanged. Leading-dot names have no extension.

// Extension validity:
// - Media (RENDERABLE_*): fixed vocabulary; membership is sufficient.
// - Non-media: retain only if the sender's browser recognizes the extension
//   (File.type is non-empty). This filters arbitrary suffixes.
// Browser-dependent heuristic; failure drops the suffix, never leaks it.
// mimeType is untrusted (postMessage); only truthiness is checked.
// "application/octet-stream" is treated as unrecognized.
function anonymizeFileName(originalName, mimeType = '') {
  if (originalName.endsWith('.age')) return originalName;
  const dot = originalName.lastIndexOf('.');
  if (dot <= 0) return 'file.age';
  const ext = originalName.slice(dot + 1).toLowerCase();
  if (!/^[a-z0-9]+$/.test(ext)) return 'file.age';
  const media = _mediaCategory(ext);
  if (media) return `${media}.${ext}.age`;
  const recognized = typeof mimeType === 'string'
    && mimeType.trim() !== ''
    && mimeType.trim().toLowerCase() !== 'application/octet-stream';
  return recognized ? `file.${ext}.age` : 'file.age';
}

// ─── Module state ─────────────────────────────────────────────────────────────

// Attachment processing guards:
//   _processedIds        — attachment already processed.
//   _inFlight            — decrypt task in progress (stable across DOM remounts).
//   _attachmentInProgress — active task for the current DOM element.

// All keys are generated by _attachId(). Mutate this state only through
// _releaseEntry(), _beginTask() and _wipeAttachmentState() below, never by
// clearing or deleting from the collections directly.

const _processedIds   = new Set();
// Keyed on stable li.id for fast React re-render.
const _decryptedCache = new Map();
// Deduplicates concurrent decrypt tasks for the same attachment (e.g. flash-jump re-inserts).
const _inFlight = new Map();
const _attachmentInProgress = new Map();
// cardKeys of spoiler attachments the user has revealed; survives virtual-scroller
// re-renders so a video being watched isn't re-covered when it scrolls back in.
const _revealedAttachments = new Set();

// Builds the "liId\0cdnUrl" key used by _processedIds, _decryptedCache,
// _inFlight, and _attachmentInProgress. Falls back to "\0<cdnUrl>"
// when the container has no id (e.g. quoted messages).
function _attachId(liElement, cdnUrl) {
  return _rootKey(liElement) + '\0' + cdnUrl;
}

// Stable DOM key of a message root. Draft-preview roots have no id but carry a
// unique data-list-item-id; keying on it keeps them from colliding with quoted
// containers that show the same attachment (both would be "\0<url>").
function _rootKey(el) {
  if (el.id) return el.id;
  const lid = el.dataset?.listItemId;
  return lid?.startsWith(DRAFT_PREVIEW_PREFIX) ? lid : '';
}

// Inverse of _attachId(): recovers the DOM liId prefix (empty for quoted
// messages) and the cdnUrl suffix from a stored key. Used by
// _evictStaleProcessedIds to check DOM liveness.
function _splitAttachId(attachId) {
  const liId = attachId.split('\0')[0];
  return { liId, url: attachId.slice(liId.length + 1) };
}

// The only place a cache entry is dropped. Media entries are { url, type,
// originalName } and own a blob: URL that must be revoked; text entries are a
// plain plaintext string and own nothing.
function _releaseEntry(attachId) {
  const cached = _decryptedCache.get(attachId);
  if (cached && typeof cached === 'object' && cached.url) URL.revokeObjectURL(cached.url);
  _decryptedCache.delete(attachId);
  _processedIds.delete(attachId);
}

// Registers a decrypt task for attachId and returns its finish() callback.
// finish() settles awaiters, which can re-enter to use the cache or retry.
// Cleanup only removes the slot if this task still owns it, preventing stale tasks
// from deleting a replacement entry after a wipe.
function _beginTask(attachId) {
  let settle;
  const promise = new Promise(res => { settle = res; });
  _inFlight.set(attachId, promise);
  return () => {
    settle();
    if (_inFlight.get(attachId) !== promise) return;
    _inFlight.delete(attachId);
    _attachmentInProgress.delete(attachId);
  };
}

// The single reset point for decrypt state (cache, in-flight work, workers).
//   includeCache=false  keeps cached plaintext/blobs (UNLOCK, same-channel nav).
//   workers='terminate' aborts media jobs (navigation, disable).
//   workers='relock'    drops the identity from both workers (RELOCK, dead context).
function _wipeAttachmentState({ includeCache = true, workers = null } = {}) {
  // The local wipe must run even if talking to a worker throws: it is what actually drops decrypted state.
  try {
    if (workers === 'relock') _relockWorkers();
    else if (workers === 'terminate') terminateFileCryptoWorker();
  } finally {
    _inFlight.clear();
    _attachmentInProgress.clear();
    if (includeCache) {
      _revealedAttachments.clear();
      for (const id of [..._decryptedCache.keys()]) _releaseEntry(id);
      _processedIds.clear();
    }
  }
}

// ─── Unlock session state ──────────────────────────────────────────────────

// Single source of truth for unlock state.
// Update via _setSession() / _clearSession().
// Gate decrypt operations with canDecrypt().
let _session = null;

// Bumped on state changes to invalidate stale async work.
// Kept outside _session so it advances independently.
let _generation = 0;

// Atomically replaces the session; callers must provide all fields.
// Never spread the prior session: zeroization would erase the shared mldsaSeedBytes.
// CONTACTS_UPDATED mutates contacts, contactsLoaded, and selfRecipient in place
// without incrementing _generation.
function _setSession(fields) {
  _session?.mldsaSeedBytes?.fill(0); // wipe any superseded key material
  _session = { ...fields };
  _generation++;
  return _session;
}

// Reverts to the locked state.
// Clears the entire session object atomically.
function _clearSession() {
  _session?.mldsaSeedBytes?.fill(0);
  _session = null;
  _generation++;
}

// The one place that defines "ready to attempt a decrypt." Requires both key
// material AND the fetched identity line.
function canDecrypt() {
  return !!(_session?.mldsaSeedBytes && _session?.cachedIdentityLine && _globalOn);
}

// Match canDecrypt() exactly: 'disabled' only for globalOff; otherwise 'locked'.
function _lockReason() {
  return (_session?.mldsaSeedBytes && _session?.cachedIdentityLine) ? 'disabled' : 'locked';
}

// Convenience accessors — every read of contacts/selfRecipient goes through
// these so callers never need a `_session?.x ?? default` inline.
function currentContacts()      { return _session?.contacts ?? {}; }
function contactsLoaded()       { return !!_session?.contactsLoaded; }
function currentSelfRecipient() { return _session?.selfRecipient ?? null; }

// In-memory only; set from the background's payload.
// Defaults to true so a missing value fails toward encrypting.
let _globalOn     = true;
let _msgObserver  = null;
let _msgObserver2 = null; // second observer for the thread-panel ol in split view

// ─── Context invalidation ─────────────────────────────────────────────────────

// Set when the extension context is invalidated.
// Checked by observers/timers to avoid browser.runtime calls after teardown.
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

  // Dead contexts cannot receive further UNLOCK/RELOCK. Clear private key
  // material immediately instead of retaining it during the reload window.
  _clearSession();
  try { _wipeAttachmentState({ workers: 'relock' }); } catch {}

  try { showAllPlaceholders('locked'); } catch {}

  window.postMessage({ type: 'AGE_CONTEXT_INVALIDATED' }, PAGE_ORIGIN);
}

// Synchronous, zero-IPC context check. Call this before any operation that
// requires a live extension context (encrypt, decrypt, sendMessage).
// Returns false and signals invalidation if the context is already dead.
function isContextValid() {
  if (_contextInvalidated) return false;
  if (!browser.runtime?.id) { _signalContextInvalidated(); return false; }
  return true;
}

// ─── DOM helpers ─────────────────────────────────────────────────────────────

// Message roots in DOM order: the <ol> lists, plus the draft preview when a
// new-thread panel is open (it replaces any open thread pane, so it takes the
// second slot).
function getMessageRoots() {
  const roots = [...document.querySelectorAll('ol[data-list-id="chat-messages"]')];
  const preview = document.querySelector(DRAFT_PREVIEW_ROOT_SEL);
  if (preview) roots.push(preview);
  return roots;
}

// ─── Draft panes (forum post / new thread) ─────────────────────────────────────

// Drafts lack a channel ID until their first message; pass them through unchanged.
// New thread: role-less <section> contains the starter preview, composer, popups,
// and drop overlay (overlay is outside the form).
// Forum post: composer/form are inside the forum list; drop overlay is its sibling,
// so classify per ancestor.
// Never a draft: anything under section[role="complementary"] (thread/forum pane).
// KEEP IN SYNC with content/upload-interceptor.js.

// DRAFT-GUARD-BEGIN
const DRAFT_FORUM_SEL   = '[data-list-id^="forum-channel-list-"]';
// Slash-command autocomplete rows also carry a NO_LIST___<index> id (role="option",
// always inside a listbox) and can appear in a real thread pane: they must not count.
const DRAFT_PREVIEW_SEL = '[data-list-item-id^="NO_LIST___"]:not([role="option"])';
const REAL_PANE_SEL     = 'section[role="complementary"]';
function isDraftTarget(el) {
  if (!el?.closest) return false;
  // New thread: the draft panel is a <section> holding the starter-message preview.
  if (el.closest('section')?.querySelector(DRAFT_PREVIEW_SEL)) return true;
  // Forum new post: the composer and its form sit inside the forum list.
  if (el.closest(DRAFT_FORUM_SEL)) return true;
  // Real thread / forum-post side panes always have a channel id.
  if (el.closest(REAL_PANE_SEL)) return false;
  // Forum page, outside the list (the new-post drop overlay is a sibling of the list):
  // draft unless the nearest ancestor that contains the list also contains a real pane
  // (then the target belongs to an open forum post, e.g. its drop overlay).
  if (!document.querySelector(DRAFT_FORUM_SEL)) return false;
  for (let n = el.parentElement; n; n = n.parentElement) {
    if (n.querySelector(DRAFT_FORUM_SEL)) return !n.querySelector(REAL_PANE_SEL);
  }
  return false;
}
// DRAFT-GUARD-END

// The draft panel's starter-message preview acts as a message root without an id
// (like a quoted message). The same attachment can also be shown elsewhere, and
// Discord reuses the message's element ids inside the preview, so it is only ever
// addressed through its root, never through document-wide id lookups.
const DRAFT_PREVIEW_PREFIX   = 'NO_LIST___';
const DRAFT_PREVIEW_ROOT_SEL = 'section form ' + DRAFT_PREVIEW_SEL;
// Every message root that has no li id: quoted messages and the draft preview.
// Discord's hashed class names have come both as "name__hash" and "name_hash";
// stem + ONE underscore matches either.
const ID_LESS_ROOT_SEL = '[class*="quotedChatMessage_"], ' + DRAFT_PREVIEW_ROOT_SEL;

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
// /channels/SERVER/CHANNEL/threads/THREAD → THREAD, otherwise null.
function getCurrentThreadId() {
  const m = THREAD_PATH_PATTERN.exec({ pathname: location.pathname });
  return m ? m.pathname.groups.threadId : null;
}

// Extracts the channel ID from a Discord CDN attachment URL.
// Uses the sender's channel ID embedded in the CDN path for signature context.
function cdnChannelId(url) {
  let m;
  try { m = CDN_ATTACHMENT_PATH_PATTERN.exec(url); } catch { return null; }
  return m ? m.pathname.groups.channelId : null;
}

// Returns the channel ID for the outgoing signature context, or null to skip
// encryption. Channel binding prevents cross-channel replay.

// A chat pane: message list + composer. The side pane is a <section>; the search
// bar also sits in a <section>, so match the complementary role, not the tag.
const CHAT_PANE_SEL = 'main, section[role="complementary"]';

// Channel shown by the pane, read from its message list.
// Rows are "chat-messages-<channelId>-<messageId>"; the intro row
// ("...-<channelId>-<channelId>") keeps empty channels resolvable.
// The pane normally shows the URL's thread/voice channel; differs only
// for stale pane state (e.g. an open thread after navigating elsewhere).
// null if the list is not rendered. 
// KEEP IN SYNC with upload-interceptor.js
const PANE_MESSAGE_ID_RE = /^chat-messages-(\d{17,20})-\d{17,20}$/;
function paneChannelId(pane) {
  const list = pane?.querySelector('ol[data-list-id="chat-messages"]');
  if (!list) return null;
  const votes = new Map();
  let best = null, bestN = 0;
  for (const el of list.querySelectorAll('[id^="chat-messages-"]')) {
    const m = PANE_MESSAGE_ID_RE.exec(el.id);
    if (!m) continue;
    const n = (votes.get(m[1]) ?? 0) + 1;
    votes.set(m[1], n);
    if (n > bestN) { best = m[1]; bestN = n; }
  }
  return best;
}

// null sends natively; drafts have no channel ID, so use focus, not the stale URL.
// Side pane (SECTION): the URL's thread, or — with no thread in the URL — the
// channel the pane itself shows (the URL's voice chat, normally the same id).
// Otherwise → CHANNEL_ID.
function getSendChannelId(fromEl) {
  const active = fromEl || document.activeElement;
  if (active && isDraftTarget(active)) return null;

  const pane = active?.closest?.(CHAT_PANE_SEL) ?? null;
  if (pane?.tagName === 'SECTION') {
    const threadId = getCurrentThreadId();
    if (threadId) return threadId;
    return paneChannelId(pane) ?? getCurrentChannelId();
  }
  return getCurrentChannelId();
}

// Returns { entry, channelId } for the specified or current channel/server,
// or null if no enabled entry matches. Server entries bind signatures to the
// server+channel pair.

// channelIdOverride/serverIdOverride use previously resolved IDs to avoid
// mixing stale and current navigation state. `undefined` re-derives IDs;
// `null` explicitly indicates no server (e.g. DMs).
function getActiveEntry(channelIdOverride, serverIdOverride) {
  const channelId = channelIdOverride !== undefined ? channelIdOverride : getCurrentChannelId();
  const serverId  = serverIdOverride !== undefined ? serverIdOverride : getCurrentServerId();
  const contacts  = currentContacts();

  if (serverId) {
    for (const entry of Object.values(contacts)) {
      if (entry.type === 'server' && entry.serverId === serverId && entry.enabled)
        return { entry, channelId };
    }
  }

  if (channelId) {
    for (const entry of Object.values(contacts)) {
      if ((entry.type === 'contact' || !entry.type) && entry.channelId === channelId && entry.enabled)
        return { entry, channelId };
      if (entry.type === 'group' && entry.channelId === channelId && entry.enabled)
        return { entry, channelId };
    }
  }
  return null;
}

// Pass the ids resolved for the composer that is sending (see getSendChannelId());
// with no args this checks the URL's parent channel only.
function isEncryptionActive(channelIdOverride, serverIdOverride) {
  const active = getActiveEntry(channelIdOverride, serverIdOverride);
  // Send side only: an entry with no recipients never encrypts.
  return canDecrypt() && !!active && entryHasRecipients(active.entry);
}

// Authoritative outbound decision, evaluated at encryption time.
// Consumed by AGE_ENCRYPT_FILE/AGE_ENCRYPT_TEXT_MESSAGE.
// 'blocked'     — explicit failure; callers throw (e.g. missing channel or recipients).
// 'passthrough' — encryption disabled, extension locked, or no channel contact configured.
// 'encrypt'     — entry and channelId are ready.

function resolveUploadGate(channelId, guildId) {
  if (!_globalOn) return { outcome: 'passthrough', reason: 'Agecord is turned off.' };
  if (!canDecrypt()) return { outcome: 'passthrough', reason: 'Agecord is locked.' };
  const active = getActiveEntry(channelId, guildId);
  if (!active?.entry) return { outcome: 'passthrough', reason: 'No encrypted contact configured for this channel.' };
  if (!entryHasRecipients(active.entry)) return { outcome: 'passthrough', reason: 'No recipients for this entry.' };
  return { outcome: 'encrypt', entry: active.entry, channelId: active.channelId };
}

// ─── Enter key interception ───────────────────────────────────────────────────

// Returns all composer textboxes (1 normally, 2 in split view): Slate editors inside a
// <form> and outside a message row. Other Slate editors (the search bar, inline message
// edit) are never returned, so a channel without a composer (system DM) yields [].
function getTextboxes() {
  return [...document.querySelectorAll('[data-slate-editor="true"]')].filter(el =>
    el.closest('form') && !el.closest('li[id^="chat-messages-"]'));
}

// Closed over `tb` so split-view composers are independently hooked.
function _makeEnterHandler(tb) {
  return (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e.altKey) return;
    // Enter confirming an IME candidate must reach Discord untouched: bail out
    // before any preventDefault/stopPropagation so the composition isn't swallowed.
    if (e.isComposing) return;
    // While an autocomplete popup (@mention, :emoji, #channel, /command) is open, Enter
    // accepts the suggestion instead of sending. Discord renders the popup inside this
    // composer's own <form>, so look only there: a listbox elsewhere (e.g. the search
    // suggestions popout) must not make Enter fall through to a native plaintext send.
    if (tb.closest('form')?.querySelector('[role="listbox"]')) return;
    const raw = tb.innerText?.trim() ?? '';
    if (!raw) return;
    // getSendChannelId() must be called synchronously — document.activeElement is
    // stable on the keydown stack, before any await. The entry is resolved for that
    // same composer (thread pane vs. parent channel), exactly as handleEncryptClick()
    // does, so the gate and the send can never disagree: no entry => native Enter.
    const sendChannelId = getSendChannelId();
    if (!sendChannelId) return;
    if (!isEncryptionActive(sendChannelId, getCurrentServerId())) return;

    // Suppress Enter after confirming we will encrypt but before the _sending check,
    // so spammed Enter presses during an in-flight cycle never reach Discord.
    e.preventDefault();
    e.stopPropagation();

    if (_sending) {
      // Encryption finished but the upload hand-off was never answered: do not swallow Enter forever.
      // Release the flag (the superseded call's finally can never run) and send afresh; the new hand-off
      // supersedes the stale one. While encryption is still running (nothing pending) Enter stays swallowed.
      if (!_pendingUpload) return;
      _sending = false;
    }
    handleEncryptClick();
  };
}

// Capture Enter before Discord's global keybind can submit plaintext from an unfocused composer.

function _outsideEnterGuard(e) {
  if (e.key !== 'Enter' || e.shiftKey || e.altKey) return;
  const target = e.target instanceof Element ? e.target : document.body;
  const composers = getTextboxes();
  // Focus inside a composer: _makeEnterHandler owns this event.
  if (composers.some(tb => tb.contains(target))) return;
  // Other text-entry widgets (search boxes, inline message edit, ...) keep their Enter.
  if (target.isContentEditable || target.closest('input, textarea, select')) return;
  const pending = composers.some(tb => {
    if (!tb.innerText?.trim()) return false;
    // Ids of the composer holding the text, not of whatever has focus.
    const channelId = getSendChannelId(tb);
    return !!channelId && isEncryptionActive(channelId, getCurrentServerId());
  });
  if (!pending) return;
  e.stopImmediatePropagation();
  // Native buttons/links keep their default action (click/navigate); Discord's keybind
  // simply never sees the key.
  if (!target.closest('button, a[href], summary')) e.preventDefault();
}

function attachEnterHook() {
  // Idempotent: the same listener + capture flag is only ever registered once.
  window.addEventListener('keydown', _outsideEnterGuard, { capture: true });
  for (const tb of getTextboxes()) {
    if (tb._ageKeyHandler) continue;
    tb._ageKeyHandler = _makeEnterHandler(tb);
    tb.addEventListener('keydown', tb._ageKeyHandler, { capture: true });
  }
}

function detachEnterHook() {
  window.removeEventListener('keydown', _outsideEnterGuard, { capture: true });
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

// Recipient format: "age1pq1...;mldsa87:<standard-base64>"
// Standard: RFC 4648 §4
// Returns the canonical base64 of the ML-DSA-87 public key, or null. Decodes and
// re-encodes so malformed base64 is rejected (fromB64 throws) and canonicalised.
function extractMldsaPubB64(recipientString) {
  const m = recipientString.match(/;mldsa87:([A-Za-z0-9+/]+=*)$/);
  if (!m) return null;
  return toB64(fromB64(m[1]));
}

// An ArrayBuffer that owns exactly the bytes of the given view (safe to transfer/clone).
function _prefixBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

// Shared by message.txt.age and media paths in processEncryptedAttachment,
// and by buildSigningContext below. Colon delimiter is safe — Discord
// snowflakes are digits only.
function buildSigPrefix(entry, channelId) {
  // A poisoned entry must not be able to inject ':' separators into the
  // signed context; the sign/verify path then fails closed.
  if (typeof channelId !== 'string' || !ID_RE.test(channelId))
    throw new Error('buildSigPrefix: invalid channelId');
  if (entry.type === 'server' && (typeof entry.serverId !== 'string' || !ID_RE.test(entry.serverId)))
    throw new Error('buildSigPrefix: invalid serverId');
  return (entry.type === 'server')
    ? new TextEncoder().encode(`${entry.serverId}:${channelId}:`)
    : new TextEncoder().encode(`${channelId}:`);
}

// Builds the worker's signing context: prefix || hint || ciphertext, assembled and signed
// in the worker (ENCRYPT / COMPRESS_ENCRYPT fuse encryption + signing).
// Shared by text/file encryption. Call BEFORE await to snapshot sender key, channel, and entry.
// Requires selfRecipient.
function buildSigningContext(entry, channelId) {
  const selfRecipient = currentSelfRecipient();
  // Locked (or never fully unlocked) between the Enter gate and the
  // encrypt: handleEncryptClick maps NOT_UNLOCKED to "extension is locked".
  // The worker can raise NOT_UNLOCKED as well (relock during an in-flight encrypt).
  if (!selfRecipient || !_session?.mldsaSeedBytes) throw new Error('NOT_UNLOCKED');

  // Hint lets the verifier find the matching key via linear scan instead of
  // calling ml_dsa87_verify against every member's key.
  const senderPubKeyB64 = extractMldsaPubB64(selfRecipient);
  if (!senderPubKeyB64) throw new Error('Own recipient has no ML-DSA-87 public key');
  if (senderPubKeyB64.length + 1 !== PUBKEY_HINT_LEN)   // the worker layout and every receiver assume PUBKEY_HINT_LEN
    throw new Error(`Unexpected sender hint length: ${senderPubKeyB64.length + 1}`);
  const prefix = buildSigPrefix(entry, channelId);      // validates ids (ID_RE) before anything reaches the worker
  if (prefix.length > SIG_BYTES)
    throw new Error('Signature prefix too long');

  return {
    prefixBuffer: _prefixBuffer(prefix),
    senderPubKeyB64,
    version:      SIG_VERSION,
    fileOffset:   SIG_VERSION_LEN,
    ...SIG_LAYOUT,
  };
}

// Returns recipient strings for outbound encryption.
// Includes all targets plus selfRecipient.
// Shared by text and file encryption paths.
// True when the entry itself has at least one usable recipient (self excluded).
function entryHasRecipients(entry) {
  const contacts = currentContacts();
  if (entry.type === 'contact' || !entry.type) return !!entry.ageRecipient;
  return (entry.memberIds ?? []).some(id => !!contacts[id]?.ageRecipient);
}

function buildRecipientList(entry) {
  const contacts   = currentContacts();
  const recipients = [];
  if (entry.type === 'contact' || !entry.type) {
    if (entry.ageRecipient) recipients.push(entry.ageRecipient.split(';')[0]);
  } else {
    for (const memberUUID of (entry.memberIds ?? [])) {
      const member = contacts[memberUUID];
      if (member?.ageRecipient) recipients.push(member.ageRecipient.split(';')[0]);
    }
  }
  const selfRecipient = currentSelfRecipient();
  if (selfRecipient) recipients.push(selfRecipient.split(';')[0]);
  // Receivers cap ciphertext at TEXT_MAX_CIPHERTEXT_BYTES, derived from MAX_RECIPIENTS: never emit more.
  if (recipients.length > MAX_RECIPIENTS) throw _blocked('Too many recipients — message too large.');
  return recipients;
}

// Returns candidate ML-DSA-87 public keys (standard-base64) that could have
// signed an incoming .age file — the contact's key plus our own recipient for
// contacts, or all member keys for groups/servers.
function buildCandidateKeysB64(entry) {
  const contacts = currentContacts();
  let keys;
  if (entry.type === 'contact' || !entry.type) {
    keys = [entry.ageRecipient];
  } else {
    const memberIds = entry.memberIds ?? [];
    keys = memberIds.map(uuid => contacts[uuid]?.ageRecipient ?? null);
  }
  const selfRecipient = currentSelfRecipient();
  if (selfRecipient) keys.push(selfRecipient);
  return keys
    .filter(Boolean)
    .map(extractMldsaPubB64)
    .filter(Boolean);
}

// ─── Base64 helpers ───────────────────────────────────────────────────────────

// Uint8Array.toBase64 / Uint8Array.fromBase64 — (Chrome 128+, Firefox 133+).

const toB64   = bytes => bytes.toBase64();
const fromB64 = b64   => Uint8Array.fromBase64(b64);

// Realm-safe ArrayBuffer brand check. In Firefox, content scripts run in a separate JS realm from the buffers they
// receive via postMessage (bridge iframe, Blob workers), so `x instanceof ArrayBuffer` is false for genuine ArrayBuffers.
// The byteLength getter throws for anything that is not a real ArrayBuffer (structured-clone safe, not spoofable).
const _abByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
function isArrayBuffer(v) { try { _abByteLength.call(v); return true; } catch { return false; } }

// Unguessable request ids. Removes predictable counters.
// The interceptor has its own copy: the two worlds cannot share code.
function newRequestId() {
  return crypto.getRandomValues(new Uint8Array(16)).toHex();
}

// Target origin for content -> page postMessage traffic (the composer plaintext travels in some replies).
const PAGE_ORIGIN = location.origin;

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

// Intl constructors cost 20–75 µs per call; instances are reusable. Cached per
// (resolved style, timezone) so a timezone change still formats correctly.
const _rtf = new Intl.RelativeTimeFormat(_userLocale, { numeric: 'auto' });
const _dtfCache = new Map();
function _getDtf(style, tz) {
  const resolved = _TIMESTAMP_OPTS[style] ? style : 'f';
  const key = resolved + '|' + tz;
  let f = _dtfCache.get(key);
  if (!f) {
    f = new Intl.DateTimeFormat(_userLocale, {
      timeZone: tz, hourCycle: _userHourCycle, ..._TIMESTAMP_OPTS[resolved],
    });
    _dtfCache.set(key, f);
  }
  return f;
}

function formatDiscordTimestamp(unixSeconds, style = 'f') {
  const tz      = Temporal.Now.timeZoneId();
  const instant = Temporal.Instant.fromEpochMilliseconds(unixSeconds * 1000);

  if (style === 'R') {
    const diffSecs = (instant.epochMilliseconds - Temporal.Now.instant().epochMilliseconds) / 1000;
    const absSecs  = Math.abs(diffSecs);
    const rtf      = _rtf;

    if (absSecs < 60)       return rtf.format(Math.round(diffSecs),        'second');
    if (absSecs < 3600)     return rtf.format(Math.round(diffSecs / 60),   'minute');
    if (absSecs < 86400)    return rtf.format(Math.round(diffSecs / 3600), 'hour');
    if (absSecs < 2592000)  return rtf.format(Math.round(diffSecs / 86400),'day');
    if (absSecs < 31536000) return rtf.format(Math.round(diffSecs / 2592000), 'month');
    return rtf.format(Math.round(diffSecs / 31536000), 'year');
  }

  return _getDtf(style, tz).format(instant.epochMilliseconds);
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
  if (_relTimestampEls.size === 0) return; // nothing scheduled — skip the <time> query
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

// Send failures are reported on the dev console with FIXED strings (engine text never goes into them).
const SEND_FAIL = {
  locked:         'extension is locked',
  noRecipients:   'no recipients for this channel',
  tooLong:        'message too long',
  encryptFailed:  'encryption failed',
  composerUnread: 'composer could not be read',
  uploadNotAcked: 'upload hand-off was not acknowledged',
};
function reportSendFailure(key) {
  // locked / no recipients / too long are user states, not bugs.
  const log = (key === 'locked' || key === 'noRecipients' || key === 'tooLong') ? console.info
            : key === 'composerUnread' ? console.warn
            : console.error;
  log(`[age] Message not sent: ${SEND_FAIL[key] ?? SEND_FAIL.encryptFailed}. Your text is still in the box.`);
}

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

// Runs in page context to access emoji DOM.
// Serializes text and converts emoji images to [name](url).
// Timeout resolves to ''; caller aborts sending and preserves composer text.
// No DOM fallback: split-view may target a different composer.

function getSlateTextViaPageContext() {
  return new Promise((resolve) => {
    const nonce = newRequestId();
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_GET_SLATE_TEXT_RESULT') return;
      if (e.data?.nonce !== nonce) return;
      window.removeEventListener('message', handler);
      clearTimeout(timer);
      // ok:false = the read FAILED (reported by the caller); ok:true with '' = an empty composer.
      resolve(e.data.ok === false ? null : (e.data.text ?? ''));
    };
    window.addEventListener('message', handler);
    window.postMessage({ type: 'AGE_GET_SLATE_TEXT', nonce }, PAGE_ORIGIN);
    const timer = setTimeout(() => {
      window.removeEventListener('message', handler);
      console.warn('[age] AGE_GET_SLATE_TEXT timed out — send aborted, text left in composer.');
      resolve(null);
    }, 500);
  });
}

// ─── Slate editor clearing ────────────────────────────────────────────────────

// Runs in page context to access the live React/Slate editor.
// Clears content via editor.deleteFragment(); synthetic beforeinput is ignored.

async function clearViaPageContext() {
  return new Promise((resolve) => {
    // Nonce ties this listener to this invocation, preventing a stale listener from
    // consuming a later call's result if the 500ms timeout already fired.
    const nonce = newRequestId();
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_CLEAR_TEXTBOX_RESULT') return;
      if (e.data?.nonce !== nonce) return;
      window.removeEventListener('message', handler);
      clearTimeout(timer);
      resolve(e.data);
    };
    window.addEventListener('message', handler);
    window.postMessage({ type: 'AGE_CLEAR_TEXTBOX', nonce }, PAGE_ORIGIN);
    const timer = setTimeout(() => {
      window.removeEventListener('message', handler);
      resolve({ ok: false, error: 'timeout' });
    }, 500);
  });
}

// Compresses and signs `plain` using the typed-message pipeline.
// Returns signed age bytes for message.txt.age upload.
// Shared by typed-send and long-text paste paths.
async function encryptTextAsMessage(plain, entry, channelId) {
  // Single choke point (typed send, paste, AGE_ENCRYPT_TEXT_MESSAGE): never emit what receivers refuse.
  if (typeof plain !== 'string' || plain.length === 0 || plain.length > MAX_INLINE_MESSAGE_CHARS)
    throw _blocked('Message empty or too long.');
  const recipients = buildRecipientList(entry);
  if (!entryHasRecipients(entry) || recipients.length === 0) throw new Error('No recipients — is an encrypted contact selected?');
  // Built BEFORE the await: one consistent snapshot of sender key, entry and channel.
  const sign   = buildSigningContext(entry, channelId);
  const signed = await workerCompressEncrypt(plain, recipients, sign);
  return new Uint8Array(signed);   // a view of the transferred buffer, no copy
}

// Sends bytes via postMessage so upload-interceptor calls React's onChange directly,
// bypassing its capture-phase DOM 'change' handler. At most one handoff is pending.
// The synchronous handler either replies or doesn't; a new Enter supersedes any unanswered request.
// No timer or magic number is needed. The id prevents mis-correlation and listener leaks,
// though MAIN-world scripts can still observe it.
let _pendingUpload = null;   // { requestId, cleanup }
function uploadSignedMessageBytes(fileBytes) {
  if (_pendingUpload) {                      // previous hand-off never answered
    reportSendFailure('uploadNotAcked');
    _pendingUpload.cleanup();                // a late reply for it is ignored
  }
  return new Promise((resolve, reject) => {
    const requestId = newRequestId();
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_DO_UPLOAD_RESULT') return;
      if (e.data.requestId !== requestId) return;
      cleanup();
      if (e.data.ok) resolve(); else reject(new Error('AGE_DO_UPLOAD failed: ' + e.data.error));
    };
    const cleanup = () => {
      window.removeEventListener('message', handler);
      if (_pendingUpload?.requestId === requestId) _pendingUpload = null;
    };
    _pendingUpload = { requestId, cleanup };
    window.addEventListener('message', handler);
    window.postMessage(
      { type: 'AGE_DO_UPLOAD', requestId, buffer: fileBytes.buffer },
      PAGE_ORIGIN,
      [fileBytes.buffer]
    );
  }); // a superseded promise simply never settles
}

// Encrypts `text` as a generic file via upload-interceptor.js.
// Used when input exceeds the message encryption limit.
const UPLOAD_TEXT_AS_FILE_TIMEOUT_MS = 25_000;
function uploadTextAsFile(text, channelId, guildId) {
  return new Promise((resolve, reject) => {
    const requestId = newRequestId();
    const timer = setTimeout(() => {
      window.removeEventListener('message', handler);
      reject(new Error('AGE_UPLOAD_TEXT_AS_FILE timeout'));
    }, UPLOAD_TEXT_AS_FILE_TIMEOUT_MS);
    const handler = (e) => {
      if (e.source !== window || e.data?.type !== 'AGE_UPLOAD_TEXT_AS_FILE_RESULT') return;
      if (e.data?.requestId !== requestId) return;
      window.removeEventListener('message', handler);
      clearTimeout(timer);
      if (e.data.ok) resolve(); else reject(new Error(e.data.error));
    };
    window.addEventListener('message', handler);
    // guildId travels with channelId through upload-interceptor.js and back
    // to our own AGE_ENCRYPT_FILE handler, so that round-trip's entry lookup
    // stays pinned to this moment too, not just this initial send.
    window.postMessage({ type: 'AGE_UPLOAD_TEXT_AS_FILE', requestId, text, channelId, guildId }, PAGE_ORIGIN);
  });
}

// Messages longer than this fit in a single encrypted message.txt.age; longer
// ones are sent as a real file instead of being silently truncated.
// KEEP IN SYNC (content/upload-interceptor.js MESSAGE_TEXT_MAX_CHARS)
const MAX_INLINE_MESSAGE_CHARS = 4000;

// Largest age ciphertext the media path will fetch/accept
// (the fetch cap, send-side check and prompt logic all derive from this one constant).
const MEDIA_MAX_CIPHERTEXT_BYTES = 2 ** 30;
// Largest plaintext file we will encrypt: leaves room for the measured worst-case send overhead at 1001
// recipients (8,085 sig/hint + 102 age fixed + 1,558,557 stanzas + 16 B per 64 KiB chunk = 1,828,888 B < 2 MiB).
const MAX_ENCRYPT_FILE_BYTES = MEDIA_MAX_CIPHERTEXT_BYTES - 2 * 1024 * 1024;
// ── Receive-path ciphertext caps. All MEASURED or DERIVED (Appendix C). ──
const MAX_SERVER_MEMBERS = 1000;                      // = popup MAX_CONTACTS
const MAX_RECIPIENTS     = MAX_SERVER_MEMBERS + 1;    // members + self
const AGE_FIXED_OVERHEAD = 102;    // header 22 + MAC 48 + payload nonce 16 + tag 16
const AGE_STANZA_BYTES   = 1557;   // one mlkem768x25519 stanza
const TEXT_MAX_PLAINTEXT_BYTES = MAX_INLINE_MESSAGE_CHARS * 3;                    // 12,000
const _deflateBound = n => n + (n >> 12) + (n >> 14) + (n >> 25) + 13;
const TEXT_CIPHERTEXT_SLACK = 4096;
const TEXT_MAX_CIPHERTEXT_BYTES =
  SIG_VERSION_LEN + SIG_BYTES + PUBKEY_HINT_LEN + AGE_FIXED_OVERHEAD +
  MAX_RECIPIENTS * AGE_STANZA_BYTES + _deflateBound(TEXT_MAX_PLAINTEXT_BYTES) + TEXT_CIPHERTEXT_SLACK;   // 1,582,855
const FILE_HEADER_LEN = SIG_VERSION_LEN + SIG_BYTES + PUBKEY_HINT_LEN;            // 8,085
// Page-facing handlers: bounded concurrency so a flood cannot queue unlimited ArrayBuffers.
const MAX_PAGE_REQUESTS_IN_FLIGHT = 8;
const ID_RE    = /^\d{1,20}$/;
const GUILD_RE = /^(?:\d{1,20}|@me)$/;

async function handleEncryptClick() {
  if (_sending) return;
  if (!canDecrypt()) return;
  // Bail immediately if the extension context has been invalidated (update/reload/disable).
  // On-demand check so the send path never attempts browser.runtime IPC against a dead context.
  if (!isContextValid()) return;
  // Set _sending before the first await so Enter presses during the ~500ms text-extraction
  // window are blocked — otherwise a second Enter would start a duplicate encrypt cycle.
  _sending = true;
  // Capture synchronously before any await — document.activeElement reflects the composer
  // that triggered the send; it may change after an await.
  const sendChannelId = getSendChannelId();
  const sendServerId  = getCurrentServerId();
  // Pass the resolved composer channelId explicitly so split-view thread
  // composers match entries keyed by the thread's channel ID.
  const active = sendChannelId ? getActiveEntry(sendChannelId, sendServerId) : null;
  if (!sendChannelId || !active || !entryHasRecipients(active.entry)) { _sending = false; return; }

  const rawPlain = await getSlateTextViaPageContext();
  if (rawPlain === null) { reportSendFailure('composerUnread'); _sending = false; return; }
  if (!rawPlain) { _sending = false; return; }   // empty composer: silent, nothing to send

  const { entry } = active;
  try {
    if (rawPlain.length > MAX_INLINE_MESSAGE_CHARS) {
      // Too long for a single encrypted message — send the full, untruncated
      // text as a real encrypted file attachment instead of cutting it down.
      await uploadTextAsFile(rawPlain, sendChannelId, sendServerId);
    } else {
      const fileBytes = await encryptTextAsMessage(rawPlain, entry, sendChannelId);
      await uploadSignedMessageBytes(fileBytes);
    }

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
      if (_trayOnGone === clearOnce) {
        // Still the active watcher (safety-timeout path): release the shared
        // observer too. If a newer send replaced _trayOnGone, leave it alone.
        _trayOnGone = null;
        _trayObserver.disconnect();
        _trayState = 'idle';
      }
      window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, PAGE_ORIGIN);
    }

    watchTrayGone(clearOnce);
    setTimeout(clearOnce, 5000); // hard safety: tray appeared but never cleared

  } catch (err) {
    const msg = err?.message ?? '';
    const key = msg === 'NOT_UNLOCKED' ? 'locked'
      : /No recipients/i.test(msg) ? 'noRecipients'
      : /too long|too large/i.test(msg) ? 'tooLong'
      : 'encryptFailed';
    // Expected states are logged (at info) by reportSendFailure; only log the raw error for real failures.
    if (key === 'encryptFailed') console.error('[age] encrypt error:', err);
    reportSendFailure(key);
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
  if (!canDecrypt()) {
    scanExistingLocked(_lockReason());
  }
  scanExisting();
  onReady?.();
}

function waitForMessageList(onReady) {
  const lists = getMessageRoots();
  if (lists.length > 0) {
    _attachToLists(lists, onReady);
    return;
  }
  // One-shot observer — fires at the exact millisecond a message root is inserted.
  // (The body-rooted reconcile pass in startNavObserver rebinds as well, which
  // covers roots that appear outside <main>.)
  const root = document.querySelector('main') ?? document.body;
  const obs = new MutationObserver(() => {
    if (_contextInvalidated) { obs.disconnect(); return; }
    const found = getMessageRoots();
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

// Returns true if a message-content-* element belongs to the given message.
// Ignores quoted-message content injected into expanded replies.
// Format: "message-content-<messageId>".
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
          if (canDecrypt()) {
            processLiFull(li);
          } else {
            showAgePlaceholder(li, _lockReason());
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

          // Nodes added INSIDE the draft preview (its card arrives after the panel).
          const preview = node.closest?.(DRAFT_PREVIEW_ROOT_SEL);
          if (preview) {
            _processQuotedContainer(preview);
            continue;
          }
          if (node.matches?.(ID_LESS_ROOT_SEL)) {
            _processQuotedContainer(node);
            continue;
          }
          node.querySelectorAll?.(ID_LESS_ROOT_SEL)
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
  // Locked/disabled: processLiFull and processQuotedMessages are no-ops anyway.
  if (!canDecrypt()) return;
  document.querySelectorAll('li[id^="chat-messages-"]').forEach(processLiFull);
  processQuotedMessages();
}

// Discord wraps spoiler attachments in a hashed-class container (spoilerContainer__xxxx)
// inside the attachment's mosaicItem_ element, around the file card. Match by substring.
const NATIVE_SPOILER_SEL = '[class*="spoilerContainer"]';

// True when the sender marked this attachment as a spoiler.
function isSpoilerAttachment(fileCard) {
  const mosaicItem = fileCard?.closest('div[class*="mosaicItem_"]');
  return !!mosaicItem?.querySelector(NATIVE_SPOILER_SEL);
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
  const text = reason === 'disabled' ? _status('Decryption disabled.', 'lock-open') : _status('Extension locked.', 'lock');
  renderDecryptedMessage(container, text, undefined, lastAnchor);
}

function showQuotedPlaceholders(reason) {
  document.querySelectorAll(ID_LESS_ROOT_SEL)
    .forEach(c => showQuotedPlaceholder(c, reason));
}

function scanExistingLocked(reason) {
  document.querySelectorAll('li[id^="chat-messages-"]').forEach(li => showAgePlaceholder(li, reason));
  showQuotedPlaceholders(reason);
}


// ─── Emoji helpers ────────────────────────────────────────────────────────────

// Discord converts typed/pasted Unicode emoji to :shortcode: in Slate before our
// TreeWalker serialises the message. Custom emoji are serialised as
// [name](cdn-url) by upload-interceptor.js.

const _shortcodeOnlyRe = /^:[a-zA-Z0-9_+\-]+:$/;

// Standard: Unicode Technical Standard #51 (UTS #51), RGI_Emoji property.

// Matches a single Unicode RGI emoji sequence.
// Covers flags, keycaps, ZWJ sequences, modifiers, and newer emoji.
// Requires the UnicodeSets ('v') flag.
const EMOJI_SEQ_RE      = /\p{RGI_Emoji}/gv;   // unanchored: scan for runs
const EMOJI_SEQ_FULL_RE = /^\p{RGI_Emoji}$/v;  // anchored: whole-string check

// CommonMark spec §6.6

// Shared link pattern used by the tokenizer and related checks.
// Intentionally supports only a restricted CommonMark link subset.
const _MDLINK_BODY   = '\\[([^\\]]{1,512})\\]\\((https://[^\\s<>"()]{1,2048})\\)';
const MDLINK_RE       = new RegExp(_MDLINK_BODY);        // unanchored: find anywhere
const MDLINK_FULL_RE  = new RegExp(`^${_MDLINK_BODY}$`);  // anchored: whole string only

// Shared Discord timestamp pattern for tokenization and validation.
// Supports documented Discord timestamp styles only.
const _TIMESTAMP_BODY   = '<t:(\\d{1,13})(?::([RfFtTdDSs]))?>';
const TIMESTAMP_RE      = new RegExp(_TIMESTAMP_BODY);       // unanchored: find anywhere
const TIMESTAMP_FULL_RE = new RegExp(`^${_TIMESTAMP_BODY}$`); // anchored: whole string only

// ── Nitro emoji URL parsing ───────────────────────────────────────────────────

// Parses Discord emoji CDN URLs.
// Returns { emojiId, ext, emojiName, isAnimated } or null.
// Validates emojiId, emojiName, ext; URLPattern pins origin and path.
const NITRO_EMOJI_URL_PATTERN = new URLPattern({
  protocol: 'https',
  hostname: 'cdn.discordapp.com',
  pathname: '/emojis/:emojiId(\\d+).:ext([a-zA-Z0-9]+)',
});
function parseNitroEmojiUrl(url) {
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

// WHATWG URL Standard §5, application/x-www-form-urlencoded serializing

// encodeURIComponent/decodeURIComponent alone do not apply this rule.
// Decode '+' before decodeURIComponent.
function decodeDiscordName(rawName) {
  // URL.searchParams.get() has already percent- and plus-decoded the value. Decoding again turned a literal
  // '+' (sent as %2B) into a space and could throw on a stray '%'. Identity by design.
  return String(rawName);
}
function encodeDiscordName(name) {
  return encodeURIComponent(name).replace(/%20/g, '+');
}

// ── Sticker URL parsing ───────────────────────────────────────────────────────

// Parses Discord sticker URLs; returns id, extension, and optional decoded name.
// Validates id/extension and safely decodes name parameters.
const STICKER_URL_PATTERN = new URLPattern({
  protocol: 'https',
  hostname: 'media.discordapp.net',
  pathname: '/stickers/:stickerId(\\d+).:ext([a-zA-Z0-9]+)',
});
function parseStickerUrl(url) {
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
    const decodedName = decodeDiscordName(rawName);
    return { stickerId, ext, decodedName };
  } catch {
    return null;
  }
}

 // Returns true if plaintext is exactly one renderable token:
 // emoji/sticker markdown, bare sticker URL, or shortcode.
function isJumboEmoji(plaintext) {
  const t = plaintext.trim();
  if (_shortcodeOnlyRe.test(t)) return true;
  if (EMOJI_SEQ_FULL_RE.test(t)) return true;
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

// ─── Obsidian UI helpers ──────────────────────────────────────────────────────

const _SVG_NS = 'http://www.w3.org/2000/svg';
const _FILL = { fill: 'currentColor', 'fill-opacity': .18 };
const _DOT  = { fill: 'currentColor', stroke: 'none' };

// name → [stroke-width, [[tag, attrs], ...]]
const _AGC_ICONS = {
  'lock': [1.75, [
    ['rect', { x: 4.75, y: 10.5, width: 14.5, height: 10.25, rx: 3.25, ..._FILL }],
    ['path', { d: 'M8 10.5V8a4 4 0 0 1 8 0v2.5' }],
    ['circle', { cx: 12, cy: 15.6, r: 1.15, ..._DOT }],
  ]],
  'lock-open': [1.75, [
    ['rect', { x: 4.75, y: 10.5, width: 14.5, height: 10.25, rx: 3.25, ..._FILL }],
    ['path', { d: 'M8 10.5V7.75a4 4 0 0 1 7.6-1.75' }],
    ['circle', { cx: 12, cy: 15.6, r: 1.15, ..._DOT }],
  ]],
  'key': [1.75, [
    ['circle', { cx: 7.5, cy: 12, r: 4.5, ..._FILL }],
    ['circle', { cx: 7.5, cy: 12, r: 1.1, ..._DOT }],
    ['path', { d: 'M12 12h8.75M17.25 12v3.25M20.75 12v2.25' }],
  ]],
  'info': [1.75, [
    ['circle', { cx: 12, cy: 12, r: 9, ..._FILL }],
    ['path', { d: 'M12 11v5.5' }],
    ['circle', { cx: 12, cy: 7.75, r: 1.1, ..._DOT }],
  ]],
  'alert': [2.25, [
    ['path', { d: 'M12 6.5v7.25' }],
    ['circle', { cx: 12, cy: 17.75, r: 1.2, ..._DOT }],
  ]],
  'check': [2.5, [
    ['path', { d: 'm6 12.75 4 4L18.25 8' }],
  ]],
  'copy': [1.9, [
    ['rect', { x: 9, y: 9, width: 11, height: 11, rx: 3, ..._FILL }],
    ['path', { d: 'M15 9V7.5A2.5 2.5 0 0 0 12.5 5h-5A2.5 2.5 0 0 0 5 7.5v5A2.5 2.5 0 0 0 7.5 15H9' }],
  ]],
  'doc': [1.75, [
    ['path', { d: 'M7.5 3.75h6L19 9.25V17.5a2.75 2.75 0 0 1-2.75 2.75h-8.5A2.75 2.75 0 0 1 5 17.5v-11A2.75 2.75 0 0 1 7.75 3.75z', ..._FILL }],
    ['path', { d: 'M13.5 4v4.25a1 1 0 0 0 1 1H19M8.75 13.25h6.5M8.75 16.5h4' }],
  ]],
  'download': [1.8, [
    ['path', { d: 'M12 4.5v10M8.25 10.75 12 14.5l3.75-3.75M5 14.5v2.25A2.75 2.75 0 0 0 7.75 19.5h8.5A2.75 2.75 0 0 0 19 16.75V14.5' }],
  ]],
};

function _agcIcon(name) {
  const [sw, parts] = _AGC_ICONS[name];
  const svg = document.createElementNS(_SVG_NS, 'svg');
  svg.setAttribute('class', 'agc-ic');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', String(sw));
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs] of parts) {
    const el = document.createElementNS(_SVG_NS, tag);
    for (const k in attrs) el.setAttribute(k, String(attrs[k]));
    svg.appendChild(el);
  }
  return svg;
}

function _agcEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}

function _makeLockMark() {
  const m = _agcEl('span', 'agc-lock');
  m.setAttribute('role', 'img');
  m.setAttribute('aria-label', 'Encrypted');
  m.appendChild(_agcIcon('lock'));
  return m;
}

function renderCodeBlock(lang, codeText) {
  const showHeader = lang && HLJS_LANGUAGES.has(lang.toLowerCase());

  const outer  = _agcEl('div', 'agc-codeblock');
  const header = _agcEl('div', showHeader ? 'agc-codehead has-lang' : 'agc-codehead');

  // Empty span keeps the copy chip right-aligned when there is no language label.
  header.appendChild(showHeader ? _agcEl('span', 'agc-lang', lang) : document.createElement('span'));

  const copyBtn = _agcEl('button', 'agc-chip');
  copyBtn.type = 'button';
  copyBtn.setAttribute('aria-label', 'Copy code');
  copyBtn.title = 'Copy code';
  const setCopied = (copied) => {
    copyBtn.classList.toggle('copied', copied);
    copyBtn.replaceChildren(_agcIcon(copied ? 'check' : 'copy'), _agcEl('span', '', copied ? 'Copied' : 'Copy'));
  };
  setCopied(false);
  let _copyResetTimer = null;
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(codeText).catch(() => {});
    setCopied(true);
    if (_copyResetTimer !== null) clearTimeout(_copyResetTimer);
    _copyResetTimer = setTimeout(() => {
      setCopied(false);
      _copyResetTimer = null;
    }, 1500);
  });
  header.appendChild(copyBtn);
  outer.appendChild(header);

  const pre  = _agcEl('pre', 'agc-codepre');
  const code = document.createElement('code');
  code.textContent = codeText;
  pre.appendChild(code);
  outer.appendChild(pre);
  return outer;
}

// Splits plaintext into text, code, and blockquote segments.
// Code fences take precedence; blockquotes require `>` + space or EOL.
// Unclosed fences remain text; only ASCII `>` is recognized.
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

  // Standard: CommonMark spec §4.5, "Fenced code blocks"

  // Fenced code block delimiter.
  // Simplified: any ``` closes an open fence.
  for (const line of lines) {
    if (inCode) {
      // Standard: CommonMark spec §4.5, closing code fence
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

    // Single-line fence: ```text``` is one Discord code block; language is not parsed.
    // The first ``` closes it; any extra backtick renders as text.
    // '.' excludes \r, \u2028, and \u2029, so reject such lines once up front to avoid
    // rescanning the tail with (.*)$ at every fence (quadratic).
    const fenceCandidate = line.trim();
    const oneLine = /[\r\u2028\u2029]/.test(fenceCandidate) ? null
      : /^```(?!`)([^\S\r\n\u2028\u2029]*\S.*?)```(.*)$/.exec(fenceCandidate);
    if (oneLine) {
      flushText();
      flushQuote();
      segments.push({ type: 'code', lang: '', text: oneLine[1] });
      if (oneLine[2].trim()) textLines.push(oneLine[2]);
      continue;
    }

    // Standard: CommonMark spec §4.5, opening code fence (a backtick fence's info string cannot contain backticks)
    const fenceMatch = /^```([^\s`]*)$/.exec(line.trimEnd());
    if (fenceMatch) {
      flushText();
      flushQuote();
      inCode    = true;
      codeLang  = fenceMatch[1];
      codeLines = [];
      continue;
    }

    // Require `>` followed by space or EOL to avoid parsing emoticons as quotes.
    // Keeps `>`, `> `, and `> text` valid quote markers.
    // Standard: CommonMark spec §5.1, Block quotes (up to 3 spaces of indent, ">" marker, optional space)
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
  const bq = _agcEl('div', 'agc-quote');

  lines.forEach((line, i) => {
    const lineSpan = _agcEl('span', 'agc-quote-line');
    applyInlineMarkdown(lineSpan, line, emojiSize);
    bq.appendChild(lineSpan);
    if (i < lines.length - 1) bq.appendChild(document.createElement('br'));
  });

  return bq;
}

// For multi-line messages the lock badge is anchored to the left of the entire
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

  // Single lock badge centered to the whole body block (matches image/video badge style).
  const outer = _agcEl('span', 'agc-block');
  outer.appendChild(_makeLockMark());

  const body = _agcEl('span', 'agc-block-body');
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
  const wrap = _agcEl('span', 'agc-line');
  if (lockPrefix) wrap.appendChild(_makeLockMark());
  // flex-wrap on inner span so tokens reflow without pulling the lock badge.
  const content = _agcEl('span', 'agc-line-body');
  applyInlineMarkdown(content, text, emojiSize);
  wrap.appendChild(content);
  return wrap;
}

// Renders `url` as a clickable link if it passes the safety check, otherwise
// appends `text` as plain text.
function appendLinkOrText(container, url, text) {
  const isSafe = URL.parse(url)?.protocol === 'https:';
  if (isSafe) {
    const a = _agcEl('a', 'agc-a', text);
    a.href   = url;
    a.target = '_blank';
    a.rel    = 'noopener noreferrer';
    container.appendChild(a);
  } else {
    container.appendChild(document.createTextNode(text));
  }
}

// ─── In-page navigation for decrypted-message links ───────────────────────────

// Routes verified same-origin Discord app links through the client router.
// External or unverified links use normal navigation.
const SPA_NAV_PATH_PREFIXES = ['/channels/', '/users/'];

function _isSpaNavTarget(url) {
  let u;
  try { u = new URL(url, location.href); } catch { return false; }
  if (u.protocol !== 'https:') return false;
  if (u.origin !== location.origin) return false;
  return SPA_NAV_PATH_PREFIXES.some(p => u.pathname.startsWith(p));
}

// Updates history and dispatches popstate to trigger Discord's client router.
// Avoids a full page reload.
function _navigateInPage(url) {
  const target = new URL(url, location.href);
  history.pushState({}, '', target.pathname + target.search + target.hash);
  window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
}

// Capture clicks on links inside [data-age-msg] before Discord handles them.
// Ignore modified and non-primary clicks to preserve default browser behavior.
document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0) return;
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = e.target?.closest?.('a[href]');
  if (!a || !a.closest('[data-age-msg]')) return;
  if (!_isSpaNavTarget(a.href)) return; // falls through to target="_blank"
  e.preventDefault();
  _navigateInPage(a.href);
}, { capture: true });

// Rejects URL-like labels to prevent destination spoofing.
// Uses URL.parse() to detect IDN/homograph domains beyond ASCII regex checks.
function isUrlLikeLabel(label) {
  const trimmed = label.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  const scheme = URL.parse(trimmed)?.protocol;
  if (scheme === 'http:' || scheme === 'https:') return true;
  // Bare domain — prepend a scheme so the parser can
  // validate/normalize the host instead of matching characters by hand.
  return !!URL.parse(`https://${trimmed}`)?.hostname.includes('.');
}

// ── applyInlineMarkdown() tag renderers ────────────────────────────────────

// Each renders one matched inline-markdown token into `container`. Split out
// of applyInlineMarkdown()'s tokenizing loop so each tag's DOM-building logic
// can be read (and changed) independently of the tokenizer driving it.

function _renderInlineCode(container, inner) {
  const code = _agcEl('code', 'agc-code-inline', inner);
  container.appendChild(code);
}

// Hides content while preserving layout dimensions for the cover overlay.
// Avoids clipping by sizing the cover from the hidden content box.
function _renderInlineSpoiler(container, inner) {
  const sp = _agcEl('span', 'agc-spoiler');

  // Until revealed, the inner span is visibility:hidden + pointer-events:none, so
  // the reveal click cannot also land on a link/emoji and fire it at the same time.
  const innerEl = _agcEl('span', 'agc-spoiler-inner');
  applyInlineMarkdown(innerEl, inner);
  sp.appendChild(innerEl);

  const cover = _agcEl('span', 'agc-spoiler-cover');
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
    // Clearing the inline style would fall back to the stylesheet's
    // visibility:hidden, so override it explicitly.
    innerEl.style.visibility = 'visible';
    innerEl.style.pointerEvents = 'auto';
  });
  container.appendChild(sp);
}

// Temporal / Intl throw RangeError outside +-8.64e15 ms (= 8.64e12 s).
const MAX_TIMESTAMP_UNIX = 8_640_000_000_000;
// Live relative ('R') timers are self-rescheduling; cap them per rendered message.
const REL_TIMERS_PER_MESSAGE = 32;
let _relBudget = REL_TIMERS_PER_MESSAGE;
function _resetRelBudget() { _relBudget = REL_TIMERS_PER_MESSAGE; }

function _renderInlineTimestamp(container, match, inner) {
  // `inner` only carries capture group 1 (the digits); re-extract the
  // optional style letter (group 2) from the full match.
  const styleMatch = TIMESTAMP_FULL_RE.exec(match);
  const style = styleMatch?.[2] ?? 'f';
  const unix  = Number(inner);
  const asText = () => container.appendChild(document.createTextNode(match));
  // Out of range (or not a safe integer): show the raw token instead of throwing mid-render.
  if (!Number.isSafeInteger(unix) || unix > MAX_TIMESTAMP_UNIX) { asText(); return; }

  let timeEl;
  try {
    const formatted = formatDiscordTimestamp(unix, style);
    const fullDate  = formatDiscordTimestamp(unix, 'F');
    timeEl = _agcEl('time', 'agc-time', formatted);
    timeEl.title    = fullDate; // hover = full date, regardless of display style
    timeEl.dateTime = Temporal.Instant.fromEpochMilliseconds(unix * 1000).toString();
  } catch { asText(); return; }

  // Only the first REL_TIMERS_PER_MESSAGE relative tokens stay live; the rest are static text.
  if (style === 'R' && _relBudget > 0) {
    _relBudget--;
    _scheduleRelUpdate(timeEl, unix);
  }

  container.appendChild(timeEl);
}

function _renderInlineMdLink(container, match, inner, emojiSize) {
  // Re-exec to extract both capture groups (label + URL); `inner` only carries group 1.
  const mdm = MDLINK_RE.exec(match);
  const label = mdm ? mdm[1] : inner;
  const url   = mdm ? mdm[2] : '';

  // Custom emoji: [name](cdn-emoji-url) where label === name= param.
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
    ].join(';');
    // Stop propagation before Discord's delegated handler sees the event; no preventDefault, so the native menu works.
    img.addEventListener('contextmenu', (e) => e.stopPropagation());
    container.appendChild(img);
    return;
  }

  // Sticker: [label](sticker-url) where label === decoded name= param.
  // Only rendered at emojiSize ≥ 48 (jumbo); otherwise falls back to plain link.
  const stickerParsed = parseStickerUrl(url);
  if (stickerParsed && stickerParsed.decodedName !== null &&
      stickerParsed.decodedName === label) {
    if (emojiSize >= 48) {
      const encodedName = encodeDiscordName(stickerParsed.decodedName);
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
      ].join(';');
      img.addEventListener('contextmenu', (e) => e.stopPropagation());
      container.appendChild(img);
      return;
    }
    if (isUrlLikeLabel(label)) {
      container.appendChild(document.createTextNode(match));
      return;
    }
    appendLinkOrText(container, url, label);
    return;
  }

  // Anti-phishing check takes priority over the safety check below regardless of outcome.
  if (isUrlLikeLabel(label)) {
    container.appendChild(document.createTextNode(match));
  } else {
    appendLinkOrText(container, url, label);
  }
}

// Built ONCE at module level; the tokenizer below keeps a per-call cursor so each regex is re-run only
// when its cached match has been consumed, instead of re-scanning the whole tail for every token.
const _INLINE_TOKENS = [
  { re: /\*\*(.+?)\*\*/s,  tag: 'strong'  },
  { re: /\*(.+?)\*/s,      tag: 'em'      },
  { re: /__(.+?)__/s,      tag: 'u'       },
  { re: /~~(.+?)~~/s,      tag: 's'       },
  // Inline triple-backtick fence (```text```) mid-line, e.g. inside ||spoilers||. Must precede the
  // single-backtick rule. The leading [^\S\n]*\S anchors the lazy body so a long run with no closing
  // delimiter is linear, not quadratic. splitBlockSegments() only handles fences that start a line.
  { re: /```(?!`)([^\S\n]*\S[^\n]*?)```(?!`)/, tag: 'fence' },
  // Double-backtick inline code (``a``).
  { re: /``(?!`)([^`]+?)``(?!`)/, tag: 'code' },
  { re: /`([^`]+)`/,       tag: 'code'    },
  { re: /\|\|(.+?)\|\|/s,  tag: 'spoiler' },
  { re: TIMESTAMP_RE, tag: 'timestamp' },
  // mdlink must come before bare link so the full [label](url) pattern is consumed
  // and the trailing ) is not left as a stray token.
  { re: MDLINK_RE, tag: 'mdlink' },
  // Allows percent-encoded paths; validates the normalized href after assignment.
  // Supports one level of parentheses.
  // Accepts apostrophes only when followed by another URL char, keeping trailing
  // punctuation outside links and quoted URLs intact. Unit starts are mutually exclusive,
  // preventing backtracking blowup.
  // Standard: GFM spec §6.9, Autolinks (extension): bare https:// URLs with balanced parentheses
  { re: /(https:\/\/(?:(?:[^\s<>"'()]|'(?=[^\s<>"'()]))*(?:\((?:[^\s<>"'()]|'(?=[^\s<>"'()]))*\)(?:[^\s<>"'()]|'(?=[^\s<>"'()]))*)*))/,  tag: 'link' },
];
// Global-flag clones for lastIndex-based scanning from a cursor.
const _INLINE_TOKENS_G = _INLINE_TOKENS.map(({ re, tag }) => ({ tag, re: new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g') }));

function applyInlineMarkdown(container, text, emojiSize = 22) {
  const cache = _INLINE_TOKENS_G.map(() => ({ m: undefined, dead: false }));
  let pos = 0;
  while (pos < text.length) {
    let earliest = null;
    for (let i = 0; i < _INLINE_TOKENS_G.length; i++) {
      const c = cache[i];
      if (c.dead) continue;
      // A cached match is still the leftmost one from `pos` unless it was consumed/overlapped.
      if (c.m === undefined || c.m.index < pos) {
        const re = _INLINE_TOKENS_G[i].re;
        re.lastIndex = pos;
        const m = re.exec(text);
        if (!m) { c.dead = true; continue; }
        c.m = m;
      }
      if (!earliest || c.m.index < earliest.index)
        earliest = { index: c.m.index, match: c.m[0], inner: c.m[1], tag: _INLINE_TOKENS_G[i].tag };
    }

    if (!earliest) { renderWithEmoji(container, text.slice(pos), emojiSize); break; }
    if (earliest.index > pos) renderWithEmoji(container, text.slice(pos, earliest.index), emojiSize);

    if (earliest.tag === 'code') {
      _renderInlineCode(container, earliest.inner);
    } else if (earliest.tag === 'fence') {
      container.appendChild(renderCodeBlock('', earliest.inner));
    } else if (earliest.tag === 'spoiler') {
      _renderInlineSpoiler(container, earliest.inner);
    } else if (earliest.tag === 'timestamp') {
      _renderInlineTimestamp(container, earliest.match, earliest.inner);
    } else if (earliest.tag === 'mdlink') {
      _renderInlineMdLink(container, earliest.match, earliest.inner, emojiSize);
    } else if (earliest.tag === 'link') {
      const url = earliest.inner;
      // Bare-link regex greedily matches concatenated URLs as one token, render as plain text instead.
      // indexOf starts at 1 to skip the leading "https://" of the match itself.
      if (url.indexOf('https://', 1) !== -1) {
        renderWithEmoji(container, url, emojiSize);
        pos = earliest.index + earliest.match.length;
        continue;
      }
      // Bare sticker URL: only rendered at emojiSize ≥ 48 (jumbo); otherwise plain link.
      const bareStickerParsed = parseStickerUrl(url);
      if (bareStickerParsed && emojiSize >= 48) {
        const encodedName = bareStickerParsed.decodedName
          ? encodeDiscordName(bareStickerParsed.decodedName)
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
        ].join(';');
        img.addEventListener('contextmenu', (e) => e.stopPropagation());
        container.appendChild(img);
      } else {
        appendLinkOrText(container, url, url);
      }
    } else {
      const el = document.createElement(earliest.tag);
      // Discord CSS resets inline tag styles; apply formatting explicitly.
      if (earliest.tag === 'strong') el.className = 'agc-strong';
      if (earliest.tag === 'em')     el.style.fontStyle = 'italic';
      if (earliest.tag === 'u')      el.style.textDecoration = 'underline';
      if (earliest.tag === 's')      el.style.textDecoration = 'line-through';
      applyInlineMarkdown(el, earliest.inner);
      container.appendChild(el);
    }

    pos = earliest.index + earliest.match.length;
  }
}

// Renders text containing :shortcode: tokens and/or Unicode emoji.
// Raw emoji not converted by Discord are matched separately so all
// emoji render with consistent sizing.
function renderWithEmoji(container, text, emojiSize = 22) {
  const shortcodeRe = /:([a-zA-Z0-9_+\-]+):/g;
  const emojiRe      = new RegExp(EMOJI_SEQ_RE.source, EMOJI_SEQ_RE.flags);
  const emojiSpanCss = `font-size:${emojiSize}px;line-height:1;display:inline-block;vertical-align:middle;flex-shrink:0;`;

  const appendGlyphSpan = (glyph) => {
    const sp = document.createElement('span');
    sp.textContent = glyph;
    sp.style.cssText = emojiSpanCss;
    container.appendChild(sp);
  };

  // Each regex keeps its next match until the cursor passes it (undefined = not scanned yet, null = exhausted).
  // Re-running the loser every iteration rescanned the whole tail for each token: quadratic on long text.
  let last = 0, smC, emC;
  while (last <= text.length) {
    if (smC === undefined || (smC && smC.index < last)) { shortcodeRe.lastIndex = last; smC = shortcodeRe.exec(text); }
    if (emC === undefined || (emC && emC.index < last)) { emojiRe.lastIndex     = last; emC = emojiRe.exec(text); }
    const sm = smC, em = emC;

    // Earliest match wins; a tie prefers the shortcode branch (it carries a
    // curated glyph lookup, so it's the more specific/authoritative match).
    let m, isShortcode;
    if (sm && (!em || sm.index <= em.index)) { m = sm; isShortcode = true; }
    else if (em)                              { m = em; isShortcode = false; }
    else break;

    if (m.index > last)
      container.appendChild(document.createTextNode(text.slice(last, m.index)));

    if (isShortcode) {
      // Own-property check: EMOJI_MAP inherits Object.prototype, so ":constructor:"
      // or ":__proto__:" would otherwise resolve to a function/object.
      const glyph = Object.hasOwn(EMOJI_MAP, m[1]) ? EMOJI_MAP[m[1]] : undefined;
      if (glyph) appendGlyphSpan(glyph);
      else container.appendChild(document.createTextNode(m[0]));
    } else {
      appendGlyphSpan(m[0]);
    }

    last = m.index + m[0].length;
  }
  if (last < text.length)
    container.appendChild(document.createTextNode(text.slice(last)));
}

// ─── Fetch iframe ─────────────────────────────────────────────────────────────

// Uses an extension iframe for cross-origin CDN fetches and zero-copy transfer.
// Lazily created, session-scoped, and recreated if removed.

let _fetchIframe   = null;
let _iframeReady   = false;
// Private MessageChannel port to the bridge document. All requests/results travel on it, never on the
// shared page window. The INIT that hands over the other end is authenticated by a per-iframe secret
// carried in the iframe URL hash (the iframe lives in a closed shadow root, so the page cannot read it).
let _bridgePort    = null;
let _iframeQueue   = [];
const _iframePending = new Map();

// Closes the current port and fails every request still waiting on it (nothing can answer them any more).
function resetBridge() {
  const port = _bridgePort;
  _bridgePort = null;
  _iframeReady = false;
  if (!port) return;
  port.onmessage = null;
  try { port.close(); } catch {}
  for (const [id, entry] of _iframePending) {
    if (entry.port !== port) continue;
    _iframePending.delete(id);
    entry.reject(Object.assign(new Error('fetch iframe replaced'), { code: 'FETCH_FAILED' }));
  }
}

function getFetchIframe() {
  if (_fetchIframe?.isConnected) return _fetchIframe;

  _fetchIframe = null;
  resetBridge();

  const host = document.createElement('div');
  host.id = 'age-fetch-iframe-host';
  host.style.cssText = 'display:none!important;position:absolute;width:0;height:0;';
  const shadow = host.attachShadow({ mode: 'closed' });

  const iframe = document.createElement('iframe');
  // One-time secret known only to this content script and the bridge document it loads.
  const secret = newRequestId();
  iframe.src = browser.runtime.getURL('content/cdn-bridge.html') + '#' + secret;
  iframe.style.cssText = 'display:none;';
  iframe.addEventListener('load', () => {
    if (_fetchIframe !== iframe || !iframe.contentWindow) return;
    const { port1, port2 } = new MessageChannel();
    _bridgePort = port1;
    port1.onmessage = onBridgeMessage;
    // '*' is acceptable: a navigated-away frame has no bridge listener, and the secret is single-use.
    iframe.contentWindow.postMessage({ type: 'AGE_BRIDGE_INIT', secret }, '*', [port2]);
  }, { once: true });
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

// Returns raw bytes via zero-copy ArrayBuffer transfer.
// Signature verification and age decryption run in file-crypto-worker.
// opts: { mode:'probe'|'full', maxBytes, allowedHints, expectedTotal? }.
// The bridge enforces streaming caps and rejects disallowed sender hints after ~8 KiB.
// Resolves { buffer?, totalBytes? }; bridge refusals reject with Error.code.
function iframePlainFetch(cdnUrl, opts) {
  return new Promise((resolve, reject) => {
    const requestId = newRequestId();
    withIframe(() => {
      const port = _bridgePort;
      if (!port) {
        reject(new Error('fetch iframe unavailable'));
        return;
      }
      _iframePending.set(requestId, { resolve, reject, port, cdnUrl });
      try {
        port.postMessage({
          type:         'AGE_FETCH_RAW',
          requestId,
          cdnUrl,
          mode:         opts.mode,
          maxBytes:     opts.maxBytes,
          prefixLen:    FILE_HEADER_LEN,
          hintOffset:   SIG_VERSION_LEN + SIG_BYTES,
          hintLen:      PUBKEY_HINT_LEN,
          allowedHints: opts.allowedHints,
          expectedTotal: opts.expectedTotal ?? null,
        });
      } catch (err) {
        _iframePending.delete(requestId);
        reject(Object.assign(new Error('fetch iframe request failed'), { code: 'FETCH_FAILED' }));
      }
    });
  });
}

// Port messages only: the page window never sees them.
function onBridgeMessage(e) {
  const d = e.data;
  if (d?.type === 'AGE_BRIDGE_READY') {
    if (_iframeReady) return;
    _iframeReady = true;
    for (const fn of _iframeQueue.splice(0)) fn();
    return;
  }

  if (d?.type === 'AGE_FETCH_RAW_RESULT') {
    const { requestId, buffer, error, code, totalBytes, cdnUrl: echoedUrl } = d;
    const entry = _iframePending.get(requestId);
    if (!entry) return;
    // Bind the reply to the URL we asked for. A mismatched reply is IGNORED (neither completes nor fails
    // the request), so the real reply can still arrive.
    if (echoedUrl !== entry.cdnUrl) return;
    _iframePending.delete(requestId);
    if (error) entry.reject(Object.assign(new Error(error), { code: typeof code === 'string' ? code : 'FETCH_FAILED' }));
    else if (buffer !== undefined && !isArrayBuffer(buffer)) entry.reject(Object.assign(new Error('bad reply'), { code: 'FETCH_FAILED' }));
    else       entry.resolve({ buffer, totalBytes: Number.isSafeInteger(totalBytes) ? totalBytes : null });
  }
}

// ─── File crypto Worker pool ──────────────────────────────────────────────────

// Separates text and media crypto workloads to avoid starvation.
// Media jobs are dispatched by byte size; text worker stays warm across navigation.

let _textWorker          = null;
let _textWorkerPending   = new Map();
let _textWorkerNextId    = 0;

// After decrypting N bytes, the media worker retains ~3N until terminated: the WASM heap
// (signature verification and signing copy the signed file), ciphertext, and decrypted chunks are retained.
// For files triggering the large-file prompt, terminate after the queue drains and lazily
// respawn (~30 ms, replaying session identity). Navigation also terminates the worker.
const MEDIA_WORKER_RECYCLE_BYTES = LARGE_FILE_THRESHOLD;
let _mediaWorker         = null;
let _mediaWorkerPending  = new Map();
let _mediaWorkerNextId   = 0;

// Each entry: { byteLength, msgArgs, transfers, resolve, reject }
const _mediaQueue     = [];
let   _mediaWorkerBusy = false;

function _spawnWorker(pendingMap) {
  // Blob Worker bridges page-origin context to extension module via dynamic import.
  // Direct extension-origin Worker construction is blocked in content scripts.
  const workerUrl = browser.runtime.getURL('content/file-crypto-worker.js');
  // The worker cannot call runtime.getURL itself, and its relative imports would resolve to the
  // real (non-dynamic) extension URL, which is blocked with use_dynamic_url. Pass getURL() URLs in.
  const libUrls   = {
    age:  browser.runtime.getURL('lib/age.min.js'),
    sign: browser.runtime.getURL('lib/agecord-sign.min.js'),
  };
  const shimSrc   = `self.__AGE_LIB_URLS=${JSON.stringify(libUrls)};import(${JSON.stringify(workerUrl)});`;
  const shimBlob  = new Blob([shimSrc], { type: 'application/javascript' });
  const shimUrl   = URL.createObjectURL(shimBlob);

  const worker = new Worker(shimUrl, { type: 'module' });
  URL.revokeObjectURL(shimUrl);

  // Buffer messages until WORKER_READY confirms the imported worker is listening.
  worker.__ageReady   = false;
  worker.__agePending = [];

  worker.onmessage = ({ data }) => {
    if (data?.op === 'WORKER_READY') {
      worker.__ageReady = true;
      const pending = worker.__agePending;
      worker.__agePending = [];
      for (const { message, transfer } of pending) worker.postMessage(message, transfer);
      return;
    }
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

// Route all worker messages through the readiness-safe send path.
function _postToWorker(worker, message, transfer) {
  // Throw instead of returning silently: a pending entry registered by the caller would never settle.
  if (!worker) throw new Error('file-crypto-worker unavailable');
  if (worker.__ageReady) worker.postMessage(message, transfer);
  else                   worker.__agePending.push({ message, transfer });
}

// Forwards UNLOCK with the current session so the worker caches its Decrypter and ML-DSA seed.
// No-op if the worker is absent or session incomplete; respawned workers replay via this path.
// Throwing here previously aborted _wipeAttachmentState/RELOCK, leaving decrypted caches unlocked.
// Send a private transferred seed copy: _postToWorker may queue until WORKER_READY, so sharing
// the session seed could let _clearSession()/_setSession() zero it before the worker receives it.
function _sendUnlockToWorker(worker) {
  if (!worker) return;
  const identityLine = _session?.cachedIdentityLine;
  if (!identityLine || !_session.mldsaSeedBytes) return;
  const mldsaSeed = _session.mldsaSeedBytes.slice();   // exact 32-byte buffer, byteOffset 0
  _postToWorker(worker, { op: 'UNLOCK', identityLine, mldsaSeed }, [mldsaSeed.buffer]);
}

function _sendRelockToWorker(worker) {
  if (!worker) return;
  _postToWorker(worker, { op: 'RELOCK' });
}

// Broadcasts UNLOCK/RELOCK to whichever file crypto workers currently exist. Every worker is always attempted and the
// first failure is rethrown afterwards, so one failing postMessage can never leave the other worker holding the identity.
function _forEachWorker(send) {
  let failure = null;
  for (const w of [_textWorker, _mediaWorker]) {
    try { send(w); } catch (e) { failure ??= e; }
  }
  if (failure) throw failure;
}

function _unlockWorkers() {
  _forEachWorker(w => _sendUnlockToWorker(w));
}

// Discards a worker. An UNLOCK still queued before WORKER_READY holds a seed copy: zero it.
// (After the READY flush the queue is empty and the buffer is detached, so nothing is zeroed twice.)
function _terminateWorker(worker) {
  if (!worker) return;
  if (worker.__agePending) {
    for (const { message } of worker.__agePending) message?.mldsaSeed?.fill(0);
    worker.__agePending.length = 0;
  }
  worker.terminate();
}

function _relockWorkers() {
  _forEachWorker(w => _sendRelockToWorker(w));
}

function getTextWorker() {
  if (!_textWorker) {
    const worker = _textWorker = _spawnWorker(_textWorkerPending);
    worker.onerror = (e) => {
      console.error('[age] file-crypto-worker (text) crashed:', e.message);
      for (const { reject } of _textWorkerPending.values())
        reject(new Error(`file-crypto-worker (text) crashed: ${e.message}`));
      _textWorkerPending.clear();
      _terminateWorker(worker);
      _textWorker = null;
    };
    // Replay UNLOCK state (identity + signing seed) via the readiness-safe worker send path.
    _sendUnlockToWorker(worker);
  }
  return _textWorker;
}

function getMediaWorker() {
  if (!_mediaWorker) {
    const worker = _mediaWorker = _spawnWorker(_mediaWorkerPending);
    worker.onerror = (e) => {
      console.error('[age] file-crypto-worker (media) crashed:', e.message);
      // Snapshot, clear and null the worker BEFORE rejecting: each reject() runs settle(), which
      // dispatches the next queued op, and that op must start on a FRESH worker, not this dead one.
      const inflight = [..._mediaWorkerPending.values()];
      _mediaWorkerPending.clear();
      _terminateWorker(worker);
      _mediaWorker = null;
      for (const { reject } of inflight)
        reject(new Error(`file-crypto-worker (media) crashed: ${e.message}`));
    };
    // Same replay as getTextWorker() — matters even more here, since this
    // worker is routinely terminated on channel nav and respawned lazily
    // while still unlocked (terminateFileCryptoWorker() does not RELOCK it).
    _sendUnlockToWorker(worker);
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
  const { byteLength, msgArgs, transfers, resolve, reject } = _mediaQueue.splice(minIdx, 1)[0];

  _mediaWorkerBusy = true;
  const id = _mediaWorkerNextId++;
  let worker = null;   // the worker this op runs on (null until spawned / if it never started)
  // One settle path: clear the pending entry, free the queue, settle the caller, start the next op.
  const settle = (fn, v) => {
    _mediaWorkerPending.delete(id);
    _mediaWorkerBusy = false;
    _maybeRecycleMediaWorker(worker);
    fn(v);
    _dispatchNextMediaOp();
  };
  _mediaWorkerPending.set(id, {
    resolve: (d) => settle(resolve, d),
    reject:  (e) => settle(reject, e),
  });
  msgArgs.id = id;
  try {
    worker = getMediaWorker();
    if (msgArgs.op === 'VERIFY_DECRYPT' || msgArgs.op === 'ENCRYPT') worker.__ageHighWater = Math.max(worker.__ageHighWater ?? 0, byteLength);
    _postToWorker(worker, msgArgs, transfers);
  } catch (e) {
    settle(reject, e);   // a synchronous throw (DataCloneError, Worker ctor) must not wedge the queue
  }
}

// byteLength is for priority ordering only, not transfer size.
// Terminates `worker` after a large verify when the queue is empty, releasing its grown heap
// after a burst while keeping it warm between large files.
// Only acts if `worker` is still THE media worker, so stale settles cannot terminate a replacement.
function _maybeRecycleMediaWorker(worker) {
  if (!worker || worker !== _mediaWorker) return;
  if (_mediaQueue.length !== 0 || _mediaWorkerPending.size !== 0) return;
  if ((worker.__ageHighWater ?? 0) < MEDIA_WORKER_RECYCLE_BYTES) return;
  _mediaWorker = null;       // the next op spawns a fresh worker and replays the identity from the session
  _terminateWorker(worker);
}
function _enqueueMediaOp(byteLength, msgArgs, transfers) {
  return new Promise((resolve, reject) => {
    _mediaQueue.push({ byteLength, msgArgs, transfers, resolve, reject });
    _dispatchNextMediaOp();
  });
}

// Terminates media jobs on navigation and clears pending queue state.
// Keeps text worker warm since it does not block channel transitions.
function terminateFileCryptoWorker() {
  // Drain the queue FIRST: with it empty, the settle()-triggered dispatch below is a no-op, so
  // navigation never spawns a new worker for a queued job (entries may hold transferred buffers).
  for (const { reject } of _mediaQueue.splice(0))
    reject(new Error('Worker terminated — channel navigation'));
  if (_mediaWorker) {
    _terminateWorker(_mediaWorker);
    _mediaWorker = null;
    const inflight = [..._mediaWorkerPending.values()];
    _mediaWorkerPending.clear();
    for (const { reject } of inflight)
      reject(new Error('Worker terminated — channel navigation'));
  }
  _mediaWorkerBusy = false;
}

// Sanity-checks a finished signed file coming back from a worker:
// [version][signature][hint][age ciphertext]. Returns the buffer.
function _checkSignedBuffer(buf) {
  if (!isArrayBuffer(buf) || buf.byteLength <= FILE_HEADER_LEN ||
      new Uint8Array(buf)[0] !== SIG_VERSION)
    throw new Error('Worker returned a malformed signed file');
  return buf;
}

// Encrypts and signs plainBuffer in the media Worker (fused ENCRYPT op).
// `sign` comes from buildSigningContext(). Resolves to the finished signed file
// ArrayBuffer [version][signature][hint][age ciphertext], transferred, not copied.
// plainBuffer is transferred and neutered; capture byteLength before postMessage.
function workerEncryptFile(plainBuffer, recipients, sign) {
  const byteLength = plainBuffer.byteLength;
  return _enqueueMediaOp(
    byteLength,
    { op: 'ENCRYPT', buffer: plainBuffer, recipients, sign },
    [plainBuffer],
  ).then(data => _checkSignedBuffer(data.buffer));
}

// Verifies and decrypts media in the isolated media Worker.
// Transfers input buffer; queued by size for priority dispatch.
function workerVerifyDecrypt(fileBuffer, prefixBytes, candidateKeysB64, fileOffset = 0) {
  const byteLength   = fileBuffer.byteLength;
  const prefixBuffer = _prefixBuffer(prefixBytes);
  return _enqueueMediaOp(
    byteLength,
    {
      op: 'VERIFY_DECRYPT',
      fileBuffer,
      candidateKeysB64,
      prefixBuffer,
      ...SIG_LAYOUT,
      fileOffset,
    },
    [fileBuffer],
  );
}

// Compress + age-encrypt + sign a plaintext string via the text Worker (COMPRESS_ENCRYPT op).
// Isolated from the media Worker so a large attachment encrypt never delays sending
// a text message. `sign` comes from buildSigningContext(). Returns Promise<ArrayBuffer> =
// the finished signed file [version][signature][hint][age ciphertext].
function workerCompressEncrypt(text, recipients, sign) {
  return new Promise((resolve, reject) => {
    const id = _textWorkerNextId++;
    _textWorkerPending.set(id, {
      resolve: (data) => {
        try { resolve(_checkSignedBuffer(data.buffer)); } catch (e) { reject(e); }
      },
      reject,
    });
    try {
      _postToWorker(getTextWorker(), { op: 'COMPRESS_ENCRYPT', id, text, recipients, sign });
    } catch (e) {
      _textWorkerPending.delete(id);
      reject(e);
    }
  });
}

// Verifies and decrypts message payloads in the dedicated text Worker.
// Transfers input buffer; kept isolated from media workloads.
function workerVerifyDecryptDecompress(fileBuffer, prefixBytes, candidateKeysB64, fileOffset = 0) {
  return new Promise((resolve, reject) => {
    const id = _textWorkerNextId++;
    _textWorkerPending.set(id, { resolve, reject });
    _postToWorker(
      getTextWorker(),
      {
        op: 'VERIFY_DECRYPT_DECOMPRESS',
        id,
        fileBuffer,
        candidateKeysB64,
        prefixBuffer: _prefixBuffer(prefixBytes),
        ...SIG_LAYOUT,
        fileOffset,
      },
      [fileBuffer]
    );
  });
}

let _pageRequestsInFlight = 0;
const _blocked = (message) => Object.assign(new Error(message), { code: 'BLOCKED' });

function listenForInterceptorMessages() {
  window.addEventListener('message', async (e) => {
    if (e.source !== window) return;
    if (e.data?.type !== 'AGE_ENCRYPT_FILE') return;

    const { requestId, fileName, mimeType } = e.data;
    const plainBuffer = e.data.buffer;
    // Captures channel context before async work to preserve composer origin.
    // Aborts when channel resolution is unreliable.
    const fileChannelId = e.data.channelId ?? null;
    const fileGuildId   = e.data.guildId ?? null;

    // Without a well-formed request id there is nobody to reply to.
    if (typeof requestId !== 'string' || requestId.length === 0 || requestId.length > 64) return;

    // ACK before any await — upload-interceptor.js's ACK_TIMEOUT_MS (2 s) detects bridge failures.
    window.postMessage({ type: 'AGE_ENCRYPT_FILE_ACK', requestId }, PAGE_ORIGIN);

    let counted = false;
    try {
      // Validate every page-supplied field before any work; fixed messages, never engine text.
      if (_pageRequestsInFlight >= MAX_PAGE_REQUESTS_IN_FLIGHT) throw _blocked('Too many requests in progress.');
      _pageRequestsInFlight++; counted = true;
      if (typeof fileName !== 'string' || fileName.length > 255 ||
          !(mimeType === undefined || (typeof mimeType === 'string' && mimeType.length <= 255)) ||
          !isArrayBuffer(plainBuffer) ||
          !(fileChannelId === null || (typeof fileChannelId === 'string' && ID_RE.test(fileChannelId))) ||
          !(fileGuildId === null || (typeof fileGuildId === 'string' && GUILD_RE.test(fileGuildId)))) {
        throw _blocked('Invalid request.');
      }
      if (plainBuffer.byteLength > MAX_ENCRYPT_FILE_BYTES) throw _blocked('File too large to encrypt.');

      // Route without a channel id: fail closed. (Drafts never get here;
      // the interceptor lets them through natively.)
      if (fileChannelId === null) {
        throw Object.assign(
          new Error('Channel ID unavailable — file not encrypted.'),
          { code: 'BLOCKED' },
        );
      }


      // Pass recipient context to avoid self-only encryption.
      // Prevents ID re-derivation after async navigation; live-evaluated.
      // A request that lands while the boot-time unlock pull is in flight must not be judged
      // against a still-empty session.
      await _awaitBootUnlock();
      const gate = resolveUploadGate(fileChannelId, fileGuildId);
      if (gate.outcome !== 'encrypt') {
        throw Object.assign(new Error(gate.reason), { code: gate.outcome.toUpperCase() });
      }

      const { entry }     = gate;
      const recipients    = buildRecipientList(entry);

      // Matched entry without usable keys must block; contact is configured.
      if (!entryHasRecipients(entry) || recipients.length === 0) {
        throw Object.assign(new Error('No recipients — is an encrypted contact selected?'), { code: 'BLOCKED' });
      }

      // Binds signatures to channel context to prevent cross-channel replay.
      // Uses captured IDs to keep signing context consistent. Built BEFORE the transfer: if it
      // throws (invalid id), plainBuffer is still attached and the catch below zero-fills it.
      const sign = buildSigningContext(entry, fileChannelId);

      // The worker encrypts AND signs; it returns the finished signed file.
      const signed = await workerEncryptFile(plainBuffer, recipients, sign);

      // Transfer back to page context — zero-copy.
      window.postMessage(
        { type: 'AGE_ENCRYPT_FILE_RESULT', requestId, buffer: signed, encryptedName: anonymizeFileName(fileName, mimeType) },
        PAGE_ORIGIN,
        [signed]
      );
    } catch (err) {
      // Refused before the worker took ownership (a transferred buffer is detached, so this is then a no-op).
      if (isArrayBuffer(plainBuffer)) new Uint8Array(plainBuffer).fill(0);
      // Gate passthrough (off/locked/no contact) and size/recipient refusals are expected, not bugs.
      const expected = err?.code === 'PASSTHROUGH' || /^(File too large|No recipients)/.test(err?.message ?? '');
      (expected ? console.info : console.error)('[age] AGE_ENCRYPT_FILE error requestId=%s:', requestId, err?.message ?? err);
      window.postMessage(
        { type: 'AGE_ENCRYPT_FILE_RESULT', requestId, error: err?.code ? err.message : 'Encryption failed.', errorCode: err?.code ?? 'BLOCKED' },
        PAGE_ORIGIN
      );
    } finally {
      if (counted) _pageRequestsInFlight--;
    }
  });

  // Long paste: encrypt via the typed-message pipeline when within
  // MAX_INLINE_MESSAGE_CHARS, producing message.txt.age.
  window.addEventListener('message', async (e) => {
    if (e.source !== window) return;
    if (e.data?.type !== 'AGE_ENCRYPT_TEXT_MESSAGE') return;

    const { requestId, text, channelId: msgChannelId, guildId: msgGuildId } = e.data;
    if (typeof requestId !== 'string' || requestId.length === 0 || requestId.length > 64) return;

    // ACK before any await — upload-interceptor.js's ACK_TIMEOUT_MS (2 s) detects bridge failures.
    window.postMessage({ type: 'AGE_ENCRYPT_TEXT_MESSAGE_ACK', requestId }, PAGE_ORIGIN);

    let counted = false;
    try {
      if (_pageRequestsInFlight >= MAX_PAGE_REQUESTS_IN_FLIGHT) throw _blocked('Too many requests in progress.');
      _pageRequestsInFlight++; counted = true;
      if (typeof text !== 'string' || text.length === 0 || text.length > MAX_INLINE_MESSAGE_CHARS ||
          !(msgChannelId === null || msgChannelId === undefined || (typeof msgChannelId === 'string' && ID_RE.test(msgChannelId))) ||
          !(msgGuildId === null || msgGuildId === undefined || (typeof msgGuildId === 'string' && GUILD_RE.test(msgGuildId)))) {
        throw _blocked('Invalid request.');
      }
      if (msgChannelId === null || msgChannelId === undefined) {
        throw Object.assign(
          new Error('Channel ID unavailable — message not encrypted.'),
          { code: 'BLOCKED' },
        );
      }

      // Both ids passed explicitly — see getActiveEntry's doc comment.
      await _awaitBootUnlock(); // see AGE_ENCRYPT_FILE
      const gate = resolveUploadGate(msgChannelId, msgGuildId ?? null);
      if (gate.outcome !== 'encrypt') {
        throw Object.assign(new Error(gate.reason), { code: gate.outcome.toUpperCase() });
      }

      const fileBytes = await encryptTextAsMessage(text, gate.entry, msgChannelId);

      window.postMessage(
        { type: 'AGE_ENCRYPT_TEXT_MESSAGE_RESULT', requestId, buffer: fileBytes.buffer },
        PAGE_ORIGIN,
        [fileBytes.buffer]
      );
    } catch (err) {
      // Gate passthrough (off/locked/no contact) and size/recipient refusals are expected, not bugs.
      const expected = err?.code === 'PASSTHROUGH' || /^(File too large|No recipients)/.test(err?.message ?? '');
      (expected ? console.info : console.error)('[age] AGE_ENCRYPT_TEXT_MESSAGE error requestId=%s:', requestId, err?.message ?? err);
      window.postMessage(
        { type: 'AGE_ENCRYPT_TEXT_MESSAGE_RESULT', requestId, error: err?.code ? err.message : 'Encryption failed.', errorCode: err?.code ?? 'BLOCKED' },
        PAGE_ORIGIN
      );
    } finally {
      if (counted) _pageRequestsInFlight--;
    }
  });
}

// Syncs unlock/key state with the upload interceptor.
// Unconfigured channels pass uploads through to Discord.
function relayInterceptorState(unlocked) {
  const active = (unlocked && _globalOn) ? !!getActiveEntry() : false;
  window.postMessage({ type: 'AGE_INTERCEPTOR_STATE', unlocked: unlocked && _globalOn, activeEntry: active }, PAGE_ORIGIN);
}

// Evicts non-DOM message cache entries and revokes blob URLs.
// Uses current DOM state; quoted messages match by CDN URL.
function _evictStaleProcessedIds() {
  if (_processedIds.size === 0) return;
  // Quoted-message containers are queried at most once per pass, not once per id.
  let quoted = null;
  for (const attachId of [..._processedIds]) {
    const { liId, url } = _splitAttachId(attachId);
    let inDom;
    if (liId) {
      // Draft-preview keys are a data-list-item-id, not an element id (Discord
      // reuses the message's real ids inside the preview).
      inDom = liId.startsWith(DRAFT_PREVIEW_PREFIX)
        ? !!document.querySelector(`section form [data-list-item-id="${CSS.escape(liId)}"]`)
        : !!document.getElementById(liId);
    } else {
      quoted ??= [...document.querySelectorAll(ID_LESS_ROOT_SEL)];
      inDom = quoted.some(c => c.querySelector(`a[href="${CSS.escape(url)}"]`));
    }
    if (!inDom) _releaseEntry(attachId);
  }
}

// ─── Extension messages ───────────────────────────────────────────────────────

// Reconcile visible messages after worker unlock so decrypt dispatch sees current state.
function _syncDisplayToSession() {
  if (_globalOn) scanExisting();
  else           showAllPlaceholders('disabled');
}

// Applies an unlock payload to session state. Shared by push and boot-time
// pull paths to keep state handling consistent.

// All unlock state arrives in one payload, avoiding partial-session async gaps.
// Validates the shape of an UNLOCK payload before anything is applied.
// Returns null when valid, else a short reason string.
const IDENTITY_LINE_PREFIXES = ['AGE-SECRET-KEY-PQ-1', 'AGE-SECRET-KEY-1'];
function _isPlainObject(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
function _recipientShapeOk(r) {
  // Same structural checks as the popup's validateRecipient().
  if (typeof r !== 'string' || !r.startsWith('age1pq1')) return false;
  // Standard: RFC 4648 §4, base64 alphabet and "=" padding
  if (!/;mldsa87:[A-Za-z0-9+/]+=*$/.test(r)) return false;
  // Standard: BIP-173 Bech32 data charset (age recipient encoding, C2SP age spec)
  return /^age1pq1[ac-hj-np-z02-9]{50,1960}$/.test(r.split(';')[0]);
}
function _unlockPayloadProblem(payload) {
  if (!_isPlainObject(payload)) return 'payload is not an object';
  if (typeof payload.mldsaSeedB64 !== 'string') return 'mldsaSeedB64 is not a string';
  let seed;
  try { seed = fromB64(payload.mldsaSeedB64); } catch { return 'mldsaSeedB64 is not base64'; }
  const len = seed.length;
  seed.fill(0);
  if (len !== 32) return 'mldsaSeedB64 does not decode to 32 bytes';
  if (typeof payload.identityLine !== 'string' ||
      !IDENTITY_LINE_PREFIXES.some(pfx => payload.identityLine.startsWith(pfx)))
    return 'identityLine is missing or malformed';
  if (!_isPlainObject(payload.contacts)) return 'contacts is not a plain object';
  if (payload.ageRecipient != null && !_recipientShapeOk(payload.ageRecipient))
    return 'ageRecipient is malformed';
  return null;
}

// There is no await here any more, so the payload is applied in
// one synchronous step and no generation bookkeeping is needed.
function applyUnlockPayload(payload) {
  const problem = _unlockPayloadProblem(payload);
  if (problem) {
    // Never half-apply: leave whatever session already existed untouched.
    console.error('[age] unlock payload rejected:', problem);
    return;
  }
  const mldsaSeedBytes = fromB64(payload.mldsaSeedB64); // 32-byte ML-DSA-87 seed

  // Single atomic publish: the prior session (if any) stays valid right up
  // until this call, and the new one is complete the instant it lands —
  // there is never a window where _session is null or partially filled in.
  _globalOn = payload.globalOn !== false;
  _setSession({
    mldsaSeedBytes,
    cachedIdentityLine: payload.identityLine,
    selfRecipient:      payload.ageRecipient || null,
    contacts:           payload.contacts,
    contactsLoaded:     true,
  });

  try {
    _wipeAttachmentState({ includeCache: false });
    // Evict stale entries so they retry; still-present cached entries skip CDN re-fetch.
    _evictStaleProcessedIds();

    // Ensures VERIFY_DECRYPT[_DECOMPRESS] sees cached state. Must happen
    // before _syncDisplayToSession()'s scanExisting() call below.
    // _unlockPayloadProblem() has already guaranteed a well-formed identityLine.
    _unlockWorkers();

    if (_globalOn) {
      attachEnterHook();
      relayInterceptorState(true);
      scheduleWarmUp();
    } else {
      // Unlocked but globally disabled — replace any stale 'locked' placeholders with 'disabled'.
      relayInterceptorState(false);
    }
  } catch (e) {
    console.error('[age] unlock error:', e);
  } finally {
    _syncDisplayToSession();
  }
}

function listenForMessages() {
  // The listener itself is synchronous and returns nothing: no response is
  // ever sent, so the channel closes immediately in every browser. The async
  // work runs in handleBackgroundMessage, whose failures are logged here.
  browser.runtime.onMessage.addListener((msg) => {
    handleBackgroundMessage(msg)
      .catch(e => console.error('[age] background message handler failed:', e?.message ?? e));
  });

  async function handleBackgroundMessage(msg) {

    if (msg?.type === 'UNLOCK') {
      await applyUnlockPayload(msg);
      return;
    }

    if (msg?.type === 'CONTACTS_UPDATED') {
      if (_contextInvalidated) return;
      const prevOn = _globalOn;
      // Applied synchronously: there is no await between reading the
      // message and publishing it, so an older update cannot overwrite newer data.
      _globalOn = msg.globalOn !== false;
      // Update session contacts without bumping _generation.
      // No-op while locked.
      if (_session) {
        if (_isPlainObject(msg.contacts)) _session.contacts = msg.contacts;
        _session.contactsLoaded = true;
        if (_recipientShapeOk(msg.ageRecipient)) _session.selfRecipient = msg.ageRecipient;
      }
      // Always re-relay when contacts change while unlocked so activeEntry in
      // upload-interceptor.js tracks the latest contacts.
      if (canDecrypt()) relayInterceptorState(true);
      else if (_globalOn !== prevOn) relayInterceptorState(!!_session?.mldsaSeedBytes);
      if (!_globalOn && prevOn) {
        _generation++;
        _wipeAttachmentState({ workers: 'terminate' });
        showAllPlaceholders('disabled');
      } else if (_globalOn) {
        // _evictStaleProcessedIds handles quoted-message entries (liId="") via DOM check.
        _evictStaleProcessedIds();
        if (_session) {
          // Mirrors the UNLOCK handler: a composer that mounted before encryption
          // was enabled never received its keydown listener (attachEnterHook is
          // idempotent, so this is a no-op for composers that already have one).
          attachEnterHook();
          scanExisting();
        }
      }
      return;
    }

    if (msg?.type === 'RELOCK') {
      _clearSession();
      // Never let a worker hiccup stop the UI from locking (the wipe itself already ran in a finally).
      try { _wipeAttachmentState({ workers: 'relock' }); } catch (e) { console.error('[age] relock: worker RELOCK failed:', e); }
      detachEnterHook();
      relayInterceptorState(false);
      showAllPlaceholders('locked');
    }
  }
}

// Pulls unlock state from background during boot. The direct request/response
// path avoids a second sendMessage round trip and listener-timing races.
// Settles when the boot-time unlock pull has finished, or after a cap so a stuck background
// worker cannot hang an upload.
const BOOT_UNLOCK_WAIT_MS = 8_000;
let _bootUnlock = Promise.resolve();
function _awaitBootUnlock() {
  let t;
  return Promise.race([_bootUnlock, new Promise(r => { t = setTimeout(r, BOOT_UNLOCK_WAIT_MS); })])
    .finally(() => clearTimeout(t));
}

async function requestUnlock() {
  try {
    const resp = await browser.runtime.sendMessage({ type: 'REQUEST_UNLOCK' });
    if (resp?.ok) await applyUnlockPayload(resp);
  } catch (e) {
    console.info('[age] REQUEST_UNLOCK failed:', e?.message);
  }
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

  // Same-document navigation is detected through the Navigation API, which covers
  // push, replace and traverse events; no History API patching is needed.
  function onNav() {
    if (_contextInvalidated) return;
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    const chanKey     = _navChannelKey(location.href);
    const chanChanged = chanKey !== lastChanKey;
    lastChanKey = chanKey;

    // Cancels previous-channel media work and invalidates stale results.
    // Prevents old ops from updating the current channel.
    _generation++;

    // li.id encodes channel ID, so a real channel change invalidates
    // _processedIds/_decryptedCache too; a same-channel nav (e.g. thread
    // panel open/close) only needs the in-flight bookkeeping cleared.
    _wipeAttachmentState({ includeCache: chanChanged, workers: 'terminate' });

    if (chanChanged) {
      // React replaces the old <ol>, bypassing normal timestamp cleanup. Clear the
      // scheduler map here instead of waiting for disconnected timers to self-expire.
      for (const { timer } of _relTimestampEls.values()) clearTimeout(timer);
      _relTimestampEls.clear();
    }
    // Keeps caches across thread suffix changes; channel key ignores thread path.
    // Handles split-view navigation without invalidating visible messages.

    _msgObserver?.disconnect();
    _msgObserver2?.disconnect();
    _msgObserver2 = null;
    waitForMessageList();
    if (_session) attachEnterHook();
    relayInterceptorState(!!_session?.mldsaSeedBytes);
  }

  navigation.addEventListener('currententrychange', onNav);

  // Reconciles message observers and Enter hooks, including detached <ol> nodes.
  // Observe <body>: panes and draft composers may exist outside <main> or open
  // without a URL change. Reconcile once per frame; attachEnterHook is idempotent.
  // Replaces the <main>-rooted composer observer.

  let _knownLists = getMessageRoots();
  let _rootsCheckQueued = false;
  new MutationObserver(() => {
    if (_rootsCheckQueued || _contextInvalidated) return;
    _rootsCheckQueued = true;
    requestAnimationFrame(() => {
      _rootsCheckQueued = false;
      _reconcileDom();
    });
  }).observe(document.body, { childList: true, subtree: true });

  function _reconcileDom() {
    if (_contextInvalidated) return;
    if (_session) attachEnterHook();
    const currentLists = getMessageRoots();
    const changed = currentLists.length !== _knownLists.length ||
      currentLists.some((l, i) => l !== _knownLists[i]);
    if (changed) {
      _knownLists = currentLists;
      _msgObserver?.disconnect();
      _msgObserver2?.disconnect();
      _msgObserver2 = null;
      waitForMessageList();
    }
  }
}

// ─── Encrypted attachment decryption ─────────────────────────────────────────

// Decrypts .age attachments and renders plaintext content inline.
// Deduplicates attachment processing by storing attachId targets.
// ── renderDecryptedAttachment() type-specific builders ─────────────────────

// Builds attachment-type-specific DOM content from decrypted blobs.
// Keeps type rendering separate from shared wrapper logic.

function _buildImageAttachment(url, strippedName) {
  const img = document.createElement('img');
  img.src   = url;
  img.alt   = strippedName;
  img.title = strippedName;
  // width/height:auto preserves intrinsic aspect ratio within the max-width/max-height caps.
  img.className = 'agc-media agc-img';
  img.addEventListener('click', () => {
    const a = document.createElement('a');
    a.href   = url;
    a.target = '_blank';
    a.rel    = 'noopener noreferrer';
    a.click();
  });
  // Stop propagation before Discord's delegated handler sees the event.
  // Do not preventDefault; this preserves the browser's native context menu.
  img.addEventListener('contextmenu', (e) => e.stopPropagation());
  const imgWrap = _agcEl('div', 'agc-att-row');
  imgWrap.appendChild(_makeLockMark());
  imgWrap.appendChild(img);
  return imgWrap;
}

function _buildVideoAttachment(url) {
  const video = document.createElement('video');
  video.src      = url;
  video.controls = true;
  video.autoplay = false;
  // Reserves media layout space via aspect-ratio before rendering.
  // Avoids fixed heights that override intrinsic proportions.
  video.className = 'agc-media agc-video';
  // Sets intrinsic aspect ratio before rendering to prevent layout shift.
  video.addEventListener('loadedmetadata', () => {
    const w = video.videoWidth;
    const h = video.videoHeight;
    if (w && h) {
      video.style.aspectRatio = w + ' / ' + h;
    }
  }, { once: true });
  // Stop propagation before Discord's delegated handler sees the event.
  // Do not preventDefault; this preserves the browser's native context menu.
  video.addEventListener('contextmenu', (e) => e.stopPropagation());

  const videoWrap = _agcEl('div', 'agc-att-row');
  videoWrap.appendChild(_makeLockMark());
  videoWrap.appendChild(video);
  return videoWrap;
}

function _buildAudioAttachment(url) {
  const audio    = document.createElement('audio');
  audio.src      = url;
  audio.controls = true;
  audio.autoplay = false;
  audio.className = 'agc-audio';
  // Stop propagation before Discord's delegated handler sees the event.
  // Do not preventDefault; this preserves the browser's native context menu.
  audio.addEventListener('contextmenu', (e) => e.stopPropagation());

  const audioWrap = _agcEl('div', 'agc-att-row');
  audioWrap.appendChild(_makeLockMark());
  audioWrap.appendChild(audio);
  return audioWrap;
}

// Generic download card: a resting tonal tile with a tonal Save chip.
function _buildDownloadCard(url, strippedName) {
  const card = _agcEl('div', 'agc-card');

  const iconWrap = _agcEl('div', 'agc-ico');
  iconWrap.appendChild(_agcIcon('doc'));

  const textCol = _agcEl('div', 'agc-meta');
  const nameSpan = _agcEl('span', 'agc-name', strippedName);
  nameSpan.title = strippedName;
  textCol.append(nameSpan, _agcEl('span', 'agc-sub', 'Encrypted file'));

  const dlBtn = _agcEl('a', 'agc-chip is-accent');
  dlBtn.href     = url;
  dlBtn.download = strippedName;
  dlBtn.rel      = 'noopener noreferrer';
  dlBtn.append(_agcIcon('download'), _agcEl('span', '', 'Save'));

  card.append(iconWrap, textCol, dlBtn);
  return card;
}

// Keep decrypted media at final size, but blurred, inert, and unfocusable until clicked.
// Wrap only the media; keep the .agc-att-row lock mark visible.
// Use the full key to avoid attachment collisions; compare in JS, never interpolate into selectors.
function _attachmentCardKey(urlOrName) { return 'age-att-' + String(urlOrName); }
function _attachmentWrappers(liElement, cardKey) {
  return [...liElement.querySelectorAll('[data-age-attachment]')].filter(el => el.dataset.ageAttachment === cardKey);
}

function _wrapAttachmentSpoiler(content, cardKey) {
  const sp = _agcEl('div', 'agc-att-spoiler');
  const innerEl = _agcEl('div', 'agc-att-spoiler-inner');
  const revealed = _revealedAttachments.has(cardKey);

  // Rows are [lock, media]; spoil the media only.
  const isRow = content.classList?.contains('agc-att-row');
  const media = isRow ? content.querySelector(':scope > :not(.agc-lock)') : null;
  const target = media ?? content;
  if (media) media.replaceWith(sp);
  innerEl.appendChild(target);
  sp.appendChild(innerEl);

  if (revealed) {
    sp.classList.add('is-revealed');
    return media ? content : sp;
  }

  innerEl.inert = true;           // not focusable/clickable/playable through the blur
  innerEl.setAttribute('aria-hidden', 'true');
  const cover = _agcEl('button', 'agc-att-spoiler-cover');
  cover.type = 'button';
  cover.setAttribute('aria-label', 'Spoiler — click to reveal');
  cover.appendChild(_agcEl('span', 'agc-att-spoiler-label', 'Spoiler'));
  cover.addEventListener('click', (e) => {
    // Reveal only; the click must not reach Discord or the media underneath.
    e.preventDefault();
    e.stopPropagation();
    _revealedAttachments.add(cardKey);
    sp.classList.add('is-revealed');
    innerEl.inert = false;
    innerEl.removeAttribute('aria-hidden');
    cover.remove();
  });
  sp.appendChild(cover);
  return media ? content : sp;
}

function renderDecryptedAttachment(liElement, fileCard, url, originalName, type, cdnUrl) {
  const strippedName = stripAgeSuffix(originalName);

  const isSpoiler = isSpoilerAttachment(fileCard);
  const mosaicItem = hideFileCard(fileCard);

  // Remove any previous render for this specific attachment only.
  // Key is derived from CDN URL (globally unique per upload) so same-named files
  // in different messages each own their own slot and never clobber each other.
  const cardKey = _attachmentCardKey(cdnUrl ?? originalName);
  _attachmentWrappers(liElement, cardKey).forEach(el => el.remove());

  // Clear any unslotted [data-age-msg] placeholder (message.txt.age clears at decrypt-start;
  // media files clear here, just before inserting the player/image/download).
  liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
    .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });

  const wrapper = document.createElement('div');
  wrapper.dataset.ageAttachment = cardKey;
  wrapper.className = 'agc agc-att';

  let body;
  if (type === 'image') {
    body = _buildImageAttachment(url, strippedName);
  } else if (type === 'video') {
    body = _buildVideoAttachment(url);
  } else if (type === 'audio') {
    body = _buildAudioAttachment(url);
  } else {
    body = _buildDownloadCard(url, strippedName);
  }
  wrapper.appendChild(isSpoiler ? _wrapAttachmentSpoiler(body, cardKey) : body);

  // Insert after the hidden mosaic item (or file card) in the DOM flow.
  const insertAfter = mosaicItem ?? fileCard;
  if (insertAfter.parentElement) {
    insertAfter.parentElement.insertBefore(wrapper, insertAfter.nextSibling);
  } else {
    liElement.appendChild(wrapper);
  }
}

// Detect forwarded messages; attachment verification is invalid because the original
// channel signing context may differ. Show a notice. Forwards structurally contain
// the original message's "message-accessories-<id>" inside their own accessories.
// Do not rely on the localised "Forwarded" header.
const ACCESSORIES_SEL = '[id^="message-accessories-"]';
function isForwardedAttachment(root) {
  for (const inner of root.querySelectorAll(ACCESSORIES_SEL)) {
    const outer = inner.parentElement?.closest(ACCESSORIES_SEL);
    if (outer && root.contains(outer)) return true;
  }
  return false;
}

// ─── Large-file confirmation prompt ──────────────────────────────────────────

// Replaces the existing [data-age-msg] spinner with a compact tonal card.
// Resolves true when the user clicks "Decrypt anyway", or false if
// _generation changes (RELOCK / disable) while the prompt is visible.
function showLargeFilePrompt(liElement, spinnerWrapper, originalName, byteLength, capturedGen) {
  // Always shown in MiB (we divide by 1024*1024); only invoked for files > LARGE_FILE_THRESHOLD.
  const sizeMib = (byteLength / (1024 * 1024)).toFixed(1);
  const thresholdMib = LARGE_FILE_THRESHOLD / (1024 * 1024);
  const displayName = stripAgeSuffix(originalName);

  // Repurpose the spinner wrapper as the prompt card — preserves DOM position.
  const wrapper = spinnerWrapper;
  wrapper.className = 'agc agc-prompt';
  // Clear the spinner badge inside.
  wrapper.replaceChildren();

  // ── Header: icon tile + name/size + lit primary action ────────────────────
  const header = _agcEl('div', 'agc-prompt-head');

  const iconWrap = _agcEl('div', 'agc-ico');
  iconWrap.appendChild(_agcIcon('lock'));

  const nameMeta = _agcEl('div', 'agc-meta');
  const nameEl = _agcEl('span', 'agc-name', displayName);
  nameEl.title = displayName;
  nameMeta.append(nameEl, _agcEl('span', 'agc-sub', `Encrypted · ${sizeMib} MiB`));

  const btn = _agcEl('button', 'agc-btn', 'Decrypt anyway');
  btn.type = 'button';

  header.append(iconWrap, nameMeta, btn);

  const warn = _agcEl('div', 'agc-note');
  warn.append(
    _agcIcon('info'),
    _agcEl('span', '',
      'Decrypting large files keeps the plaintext in memory until this tab is closed. '
      + `Files over ${thresholdMib} MiB may increase memory usage significantly.`),
  );

  wrapper.append(header, warn);

  // Return a Promise that resolves true on click, false on generation change.
  return new Promise((resolve) => {
    btn.addEventListener('click', () => {
      // Clear the prompt content — renderDecryptedMessage(null) will re-insert
      // the spinner into this same wrapper node immediately after we return.
      wrapper.replaceChildren();
      wrapper.className = 'agc agc-msg';
      resolve(true);
    }, { once: true });

    // Cancels stale prompts when session state changes.
    // Normal rendering restores the correct badge state.
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

// Checks decrypt readiness after async work.
// Returns ready, locked, no-entry, or retry.
function checkDecryptPreconditions() {
  if (!_session?.cachedIdentityLine) return { ready: false, reason: 'locked' };
  const active = getActiveEntry();
  if (!active) return { ready: false, reason: contactsLoaded() ? 'no-entry' : 'retry' };
  return { ready: true, active };
}

// Deduplicates attachment processing across observer events.
// Reuses same-element work; retries after stale element tasks settle.
async function _awaitStaleInFlight(attachId, liElement, fileCard, cdnUrl, originalName, previousRoot) {
  if (!_inFlight.has(attachId)) return false;
  if (previousRoot === liElement) return true; // same node, already running
  try { await _inFlight.get(attachId); } catch { /* ignore Task A errors */ }
  await processEncryptedAttachment(liElement, fileCard, cdnUrl, originalName);
  return true;
}

async function processEncryptedAttachment(liElement, fileCard, cdnUrl, originalName, previousRoot) {
  // isContextValid() calls _signalContextInvalidated() which swaps all placeholders to 'locked'.
  if (!isContextValid()) return;

  // Exit early if no active entry.
  // Callers guarantee canDecrypt(); gate on contactsLoaded().
  if (contactsLoaded() && !getActiveEntry()) {
    _attachmentInProgress.delete(_attachId(liElement, cdnUrl));
    const _noEntryMosaicItem = hideFileCard(fileCard);
    renderDecryptedMessage(liElement, _status('No entry configured for this channel.', 'key'), undefined, _noEntryMosaicItem ?? fileCard);
    return;
  }

  // ── Forwarded message guard ───────────────────────────────────────────────────

  // See isForwardedAttachment() — runs after the entry check above so
  // "No entry configured" takes precedence.
  if (isForwardedAttachment(liElement)) {
    _attachmentInProgress.delete(_attachId(liElement, cdnUrl));
    const mosaicItem = hideFileCard(fileCard);
    renderDecryptedMessage(liElement, _status('Message forwarding is not supported.', 'alert', true), null, mosaicItem ?? fileCard);
    return;
  }

  // ── message.txt.age — treat as encrypted text message ────────────────────────

  if (originalName === 'message.txt.age') {
    return _processEncryptedTextMessage(liElement, fileCard, cdnUrl, originalName, previousRoot);
  }

  return _processEncryptedMediaAttachment(liElement, fileCard, cdnUrl, originalName, previousRoot);
}

// Handles message.txt.age decryption and inline rendering.
// Keeps text decrypt flow separate from media processing.
async function _processEncryptedTextMessage(liElement, fileCard, cdnUrl, originalName, previousRoot) {
  {
    // Key includes li.id so two message.txt.age files in the same message
    // (same liElement.id, different CDN URLs) get separate cache/in-flight slots.
    const attachId = _attachId(liElement, cdnUrl);

    // Serve from cache on re-render — no CDN fetch needed.
    if (_processedIds.has(attachId)) {
      const cached = _decryptedCache.get(attachId);
      if (cached) {
        // Re-render only if the wrapper is missing after virtual-scroller reinsertion.
        // Use _rootShowsSlot: attachId contains NUL, which CSS.escape() replaces with U+FFFD.
        // Always call hideFileCard to re-hide cards recreated by Discord.

        const mosaicItem = hideFileCard(fileCard);
        if (!_rootShowsSlot(liElement, attachId)) {
          try {
            renderDecryptedMessage(liElement, cached, attachId, mosaicItem ?? fileCard);
          } catch (e) {
            // A cached plaintext that cannot be rendered must not throw outside any try on every re-render.
            console.error('[age] cached message render failed:', e?.message ?? e);
            _releaseEntry(attachId);
            try { renderDecryptedMessage(liElement, _status("Couldn't display message.", 'lock-open'), attachId, mosaicItem ?? fileCard); } catch { }
          }
        }
      }
      return;
    }

    // ── In-flight deduplication ───────────────────────────────────────────────

    // Deduplicates concurrent attachment tasks by attachId and element.
    // Reuses in-flight work; stale elements retry through cache.
    if (await _awaitStaleInFlight(attachId, liElement, fileCard, cdnUrl, originalName, previousRoot)) return;

    // No in-flight task — start one and expose the Promise so a concurrent
    // call for the same attachId can await it.
    const finishTask = _beginTask(attachId);

    // A placeholder from showAgePlaceholder (locked/disabled) has no slot key —
    // clear it now so it doesn't survive alongside the result.
    liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
      .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });

    const capturedGeneration = _generation;
    // Hoisted so the catch block can reference it for error rendering.
    let mosaicItem = fileCard.closest('div[class*="mosaicItem_"]');

    try {
      if (_generation !== capturedGeneration) return;

      // ── Fetch CDN bytes ────────────────────────────────────────────────

      // Identity was fetched at UNLOCK and cached in the file crypto workers.
      // Candidate signers are needed before download so the bridge can reject unauthenticated
      // files after ~8 KiB. If unavailable, skip download; the recheck renders the status.
      let fileBuffer = null;
      const pre = checkDecryptPreconditions();
      if (pre.ready) {
        ({ buffer: fileBuffer } = await iframePlainFetch(cdnUrl, {
          mode: 'full', maxBytes: TEXT_MAX_CIPHERTEXT_BYTES,
          allowedHints: buildCandidateKeysB64(pre.active.entry),
        }));
      }
      if (_generation !== capturedGeneration) return;

      // Capture AFTER the awaits — session/contacts are now stable.
      const precheck = checkDecryptPreconditions();

      if (!precheck.ready) {
        if (precheck.reason === 'locked') {
          // Extension locked mid-flight — retriable once unlocked.
          mosaicItem = hideFileCard(fileCard);
          renderDecryptedMessage(liElement, _status('Extension locked.', 'lock'));
        } else if (precheck.reason === 'no-entry') {
          // Skips channels without configured entries.
          // Clears attachment state so future updates can retry.
          mosaicItem = hideFileCard(fileCard);
          renderDecryptedMessage(liElement, _status('No entry configured for this channel.', 'key'));
        }
        // else reason === 'retry': contacts genuinely haven't arrived from the
        // background yet — the finally block releases so the next UNLOCK/
        // scanExisting can retry with real contacts.
        return;
      }
      if (!fileBuffer) return;   // became ready only after the skipped download: retry on next scan
      const capturedActive = precheck.active;

      // Contacts loaded and we have an active entry — show the decrypting
      // placeholder now that we're committed to real work.
      mosaicItem = hideFileCard(fileCard);
      renderDecryptedMessage(liElement, null, attachId, mosaicItem ?? fileCard);

      if (fileBuffer.byteLength < SIG_VERSION_LEN + SIG_BYTES + 1) throw new Error('message.txt.age too short');

      // The version byte (SIG_VERSION) was already enforced by the bridge (checkHeader) before
      // any bytes reached this script, so no version check is needed here.
      // No slice: the worker reads the signature at SIG_VERSION_LEN inside the same buffer.

      // ── Build sig prefix and candidate key list ─────────────────────

      // Builds signature prefix and candidate keys for verification.
      // Uses CDN channel ID to match the sender's signing context.
      const { entry } = capturedActive;
      const msgCdnChannelId = cdnChannelId(cdnUrl);
      if (!msgCdnChannelId) throw new Error('Could not extract channel ID from CDN URL');
      const prefix = buildSigPrefix(entry, msgCdnChannelId);
      const candidateKeysB64 = buildCandidateKeysB64(entry);

      if (_generation !== capturedGeneration) return;

      // ── Fused verify + decrypt + decompress in the Worker ────────────

      // Transfers fileBuffer zero-copy; worker performs ML-DSA-87 verify,
      // age decrypt, and deflate-raw decompress off the main thread, returning
      // { sigValid, plaintext } in one round-trip.
      const workerResult = await workerVerifyDecryptDecompress(
        fileBuffer, prefix, candidateKeysB64, SIG_VERSION_LEN
      );
      // Checked again after the worker await — a RELOCK/UNLOCK during the
      // worker run bumps _generation; writing stale plaintext into the new
      // session's cache would be a cross-session leak.
      if (_generation !== capturedGeneration) return;

      if (!workerResult.sigValid) {
        renderDecryptedMessage(liElement, _sigFailureStatus(workerResult), attachId, mosaicItem ?? fileCard);
        return;
      }

      if (workerResult.reason === 'not-recipient') {
        renderDecryptedMessage(liElement, _notRecipientStatus(), attachId, mosaicItem ?? fileCard);
        return;
      }

      const { plaintext } = workerResult;

      // Cache only AFTER a successful render: a render that throws must not leave a poisoned entry,
      // and is a display failure, not a decrypt failure.
      try {
        renderDecryptedMessage(liElement, plaintext, attachId, mosaicItem ?? fileCard);
      } catch (re) {
        console.error('[age] message render failed:', re?.message ?? re);
        renderDecryptedMessage(liElement, _status("Couldn't display message.", 'lock-open'), attachId, mosaicItem ?? fileCard);
        return;
      }
      _processedIds.add(attachId);
      _decryptedCache.set(attachId, plaintext);

    } catch (e) {
      // A generation change means showAllPlaceholders already wrote the
      // correct status — don't overwrite it with "Couldn't decrypt."
      if (_generation !== capturedGeneration) return;
      // Checks extension state before showing decrypt errors.
      // Avoids masking context invalidation as a decryption failure.
      if (!isContextValid()) return;
      const _errMosaicItem = hideFileCard(fileCard);
      if ((e?.message ?? e) === 'NOT_UNLOCKED') {
        // NOT_UNLOCKED indicates a worker-state race; otherwise treat it as a regression.
        console.error('[age] NOT_UNLOCKED decrypting text attachment — worker desynced from session state:', { attachId });
        renderDecryptedMessage(liElement, _status('Extension locked.', 'lock'), attachId, _errMosaicItem ?? fileCard);
        return;
      }
      const _tf = _transportFailureStatus(e);
      if (_tf) {
        console.info('[age] message.txt.age not decrypted:', e?.code ?? e?.message);
        renderDecryptedMessage(liElement, _tf, attachId, _errMosaicItem ?? fileCard);
        return;
      }
      console.info('[age] message.txt.age decrypt skipped (not a valid age file or not encrypted):', e?.message ?? e);
      renderDecryptedMessage(liElement, _status("Couldn't decrypt.", 'lock-open'), attachId, _errMosaicItem ?? fileCard);
    } finally {
      // Single release point for every exit above.
      finishTask();
    }
  }
}

// Handles media and download attachment decryption/rendering.
// Keeps large-file flow separate from message text decryption.
async function _processEncryptedMediaAttachment(liElement, fileCard, cdnUrl, originalName, previousRoot) {
  // ── All other .age files — media/download attachments ────────────────────────

  // Capture generation now — RELOCK or globalOn→false bumps it synchronously,
  // preventing a stale result from re-inserting media after disable/lock.
  const capturedGeneration = _generation;
  const attachId = _attachId(liElement, cdnUrl);

  // ── Media cache-hit: already decrypted, wrapper still in DOM — skip entirely ──

  // Reuses cached decrypted media to avoid duplicate fetch/decrypt work.
  // Re-renders from cached blob when virtualized DOM nodes are replaced.
  if (_processedIds.has(attachId)) {
    const cached = _decryptedCache.get(attachId);
    if (cached?.url) {
      // Recompute the same cardKey used by renderDecryptedAttachment to check
      // whether its wrapper div is still present.
      const cardKey = _attachmentCardKey(cdnUrl);
      if (_attachmentWrappers(liElement, cardKey).length > 0) {
        return; // wrapper present — nothing to do
      }
      // Wrapper recycled; re-render from cache. _releaseEntry revokes and
      // removes cache entries atomically, so a cached entry implies a live blob URL.
      hideFileCard(fileCard);
      renderDecryptedAttachment(liElement, fileCard, cached.url, cached.originalName, cached.type, cdnUrl);
    }
    return;
  }

  // ── In-flight deduplication for media path ───────────────────────────────────

  // Deduplicates media fetches across virtual-scroller remounts.
  // Uses attachId tracking to prevent duplicate worker queue entries.
  if (await _awaitStaleInFlight(attachId, liElement, fileCard, cdnUrl, originalName, previousRoot)) return;

  // No in-flight task — start one and expose the Promise so concurrent calls
  // for the same attachId can await it.
  const finishTask = _beginTask(attachId);

  // ── Show "Decrypting…" placeholder immediately ────────────────────────────────

  // Shows decrypt status before network work begins.
  // Replaces placeholder with result or error after processing.
  const _earlyMosaicItem = hideFileCard(fileCard);
  renderDecryptedMessage(liElement, null, undefined, _earlyMosaicItem ?? fileCard);

  // Decrypted bytes from the worker; zeroed in finally on every exit path.
  let plainBytes = null;
  try {
    // ── Fetch CDN bytes ────────────────────────────────────────────────

    // The identity line was already fetched once at UNLOCK and cached
    // in the file crypto workers.
    // Probe first: a ranged request for the 8,085-byte header gives the total size and
    // the sender hint, so the prompt and the signer check happen BEFORE the body is downloaded.
    let fileBuffer = null;
    const pre = checkDecryptPreconditions();
    if (pre.ready) {
      const allowedHints = buildCandidateKeysB64(pre.active.entry);
      const probe = await iframePlainFetch(cdnUrl, { mode: 'probe', maxBytes: MEDIA_MAX_CIPHERTEXT_BYTES, allowedHints });
      if (_generation !== capturedGeneration) return;
      const totalBytes = probe.totalBytes;

      // Capture the spinner wrapper so showLargeFilePrompt can mutate it in-place.
      const spinnerWrapper = liElement.querySelector('[data-age-msg]:not([data-age-msg-slot])');
      if (totalBytes > LARGE_FILE_THRESHOLD) {
        const confirmed = await showLargeFilePrompt(
          liElement, spinnerWrapper, originalName, totalBytes, capturedGeneration
        );
        if (!confirmed || _generation !== capturedGeneration) return;
        // Re-insert the spinner — prompt cleared the wrapper on resolve.
        renderDecryptedMessage(liElement, null, undefined, _earlyMosaicItem ?? fileCard);
      }
      if (_generation !== capturedGeneration) return;

      ({ buffer: fileBuffer } = await iframePlainFetch(cdnUrl, {
        mode: 'full', maxBytes: Math.min(MEDIA_MAX_CIPHERTEXT_BYTES, totalBytes),
        expectedTotal: totalBytes, allowedHints,
      }));
      if (_generation !== capturedGeneration) return;
    }

    // ── Identity + entry check — required for sig prefix and candidate key list ──
    // Capture AFTER the awaits — session/contacts are now stable.
    const precheck = checkDecryptPreconditions();
    if (!precheck.ready) {
      if (precheck.reason === 'locked') {
        const _lockedMosaicItem = hideFileCard(fileCard);
        renderDecryptedMessage(liElement, _status('Extension locked.', 'lock'), undefined, _lockedMosaicItem ?? fileCard);
      } else if (precheck.reason === 'no-entry') {
        // contacts loaded, entry missing (including zero contacts configured) → not a retriable error
        const _noEMosaicItem = hideFileCard(fileCard);
        renderDecryptedMessage(liElement, _status('No entry configured for this channel.', 'key'), undefined, _noEMosaicItem ?? fileCard);
      }
      // reason === 'retry': contacts haven't arrived yet — release silently, matches text path.
      return;
    }
    if (!fileBuffer) return;   // became ready only after the skipped download: retry on next scan
    const capturedActive = precheck.active;

    if (fileBuffer.byteLength < SIG_VERSION_LEN + SIG_BYTES + 1) throw new Error('media .age file too short');

    // Alias _earlyMosaicItem for consistent naming in the rest of this function.
    const _attMosaicItem = _earlyMosaicItem;

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

    // Transfers fileBuffer zero-copy; worker performs ML-DSA-87 verify and
    // age decrypt off the main thread, returning { sigValid, buffer }.
    // No decompress step — media files are already compressed by their codecs.
    const workerResult = await workerVerifyDecrypt(
      fileBuffer, prefix, candidateKeysB64, SIG_VERSION_LEN
    );
    if (workerResult.buffer) plainBytes = new Uint8Array(workerResult.buffer);
    // RELOCK/UNLOCK during the worker run bumps _generation.
    if (_generation !== capturedGeneration) return;

    if (!workerResult.sigValid) {
      liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
        .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
      renderDecryptedMessage(liElement, _sigFailureStatus(workerResult), undefined, _attMosaicItem ?? fileCard);
      return;
    }

    if (workerResult.reason === 'not-recipient') {
      liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
        .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
      renderDecryptedMessage(liElement, _notRecipientStatus(), undefined, _attMosaicItem ?? fileCard);
      return;
    }

    const type     = classifyFile(originalName);
    const ext      = stripAgeSuffix(originalName).split('.').pop().toLowerCase();
    const mimeType = { image: 'image/' + ext, video: 'video/' + ext, audio: 'audio/' + ext }[type]
                  ?? 'application/octet-stream';

    // Blob copies the bytes, so plainBytes is zeroed in finally.
    const url = URL.createObjectURL(new Blob([plainBytes], { type: mimeType }));
    try {
      renderDecryptedAttachment(liElement, fileCard, url, originalName, type, cdnUrl);
    } catch (re) {
      URL.revokeObjectURL(url); // not cached yet, so nothing else would free it
      throw re;
    }
    // Cache blob URL + metadata for re-renders. Released only by _releaseEntry.
    _processedIds.add(attachId);
    _decryptedCache.set(attachId, { url, type, originalName });

  } catch (e) {
    if (_generation !== capturedGeneration) return;
    if (!isContextValid()) return;
    // Transport/size refusals are handled outcomes (shown as a status), not extension errors.
    if (_transportFailureStatus(e)) console.info('[age] attachment not decrypted:', e?.code ?? e?.message);
    else console.error('[age] attachment decrypt error:', e?.message ?? e);
    // Replace the "Decrypting…" placeholder with an error badge.
    liElement.querySelectorAll('[data-age-msg]:not([data-age-msg-slot])')
      .forEach(el => { _clearRelTimestampsIn(el); el.remove(); });
    if ((e?.message ?? e) === 'NOT_UNLOCKED') {
      // Only expected for a RELOCK race; already logged by the catch handler.
      renderDecryptedMessage(liElement, _status('Extension locked.', 'lock'), undefined, _earlyMosaicItem ?? fileCard);
      return;
    }
    renderDecryptedMessage(liElement, _transportFailureStatus(e) ?? _status("Couldn't decrypt.", 'lock-open'), undefined, _earlyMosaicItem ?? fileCard);
  } finally {
    plainBytes?.fill(0);
    finishTask();
  }
}

// ─── Status badge helpers ─────────────────────────────────────────────────────

// Tagged status notice: text + icon name (see _AGC_ICONS). Danger tint is
// reserved for errors; locked/disabled/info states stay unlit.
function _status(text, icon, danger = false) {
  return { status: text, icon, danger };
}

// Maps a transport/size refusal (bridge code, or the worker's TEXT_TOO_LARGE) to its own status;
// never "Signature invalid" for a transport problem. Returns null for anything else.
function _transportFailureStatus(e) {
  const k = e?.code ?? e?.message;
  switch (k) {
    case 'TEXT_TOO_LARGE':   return _status('Message too large.', 'info');
    case 'TOO_LARGE':        return _status('File too large to decrypt.', 'info');
    case 'HINT_REJECTED':    return _status('Unknown sender — not a member of this entry.', 'key');
    case 'TOO_SHORT':        return _status("Couldn't decrypt.", 'lock-open');
    case 'NOT_RANGEABLE':    return _status('Download refused: the server did not honour a safe partial request.', 'info');
    case 'LENGTH_MISMATCH':  return _status('Download refused: the file size changed or did not match.', 'info');
    case 'BAD_REQUEST':
    case 'FETCH_FAILED':     return _status('Download failed — could not fetch this file.', 'info');
    default:                 return null;
  }
}

// Maps a failed VERIFY_DECRYPT* result to a status. An unlisted sender key is
// not tampering, so it gets a neutral notice instead of the danger alert.
function _sigFailureStatus(workerResult) {
  if (workerResult?.reason === 'unknown-sender')
    return _status('Unknown sender — not a member of this entry.', 'key');
  return _status('Signature invalid — possible tampering.', 'alert', true);
}

// Validly signed by a known member but encrypted to other recipients. Not an
// error and not tampering, so a neutral notice.
function _notRecipientStatus() {
  return _status("This message wasn't encrypted for you.", 'key');
}

// Builds a status chip: icon (decorative, non-selectable) + selectable text.
function _makeStatusBadge(text, icon, danger) {
  const outer = _agcEl('span', danger ? 'agc-status is-danger' : 'agc-status');
  outer.appendChild(_agcIcon(icon));
  outer.appendChild(_agcEl('span', 'agc-status-text', text));
  return outer;
}

function _makeSpinnerBadge(text) {
  const outer = _agcEl('span', 'agc-status');
  outer.setAttribute('role', 'status');
  outer.append(_agcEl('span', 'agc-spinner'), _agcEl('span', 'agc-status-text', text));
  return outer;
}

// Cached template for the "Decrypting..." spinner badge.
// cloneNode(true) is cheaper than rebuilding the element tree on every
// in-flight attachment. Built lazily so document is guaranteed to be available.
let _decryptingBadgeTemplate = null;
function _makeDecryptingBadge() {
  if (!_decryptingBadgeTemplate)
    _decryptingBadgeTemplate = _makeSpinnerBadge('Decrypting\u2026');
  return _decryptingBadgeTemplate.cloneNode(true);
}

// Renders decrypt state or status for a text attachment.

// slotKey isolates concurrent attachment updates within a li.
// insertAfter preserves attachment ordering relative to file cards.
function renderDecryptedMessage(liElement, plaintext, slotKey, insertAfter) {
  _resetRelBudget();   // fresh live-timer budget per rendered message
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
  // .agc-msg sets overflow-wrap:anywhere (breaks long unbreakable tokens such as
  // URLs and base64) and min-width:0 (lets flex children shrink below content size).
  wrapper.className = 'agc agc-msg';

  if (plaintext === null) {
    // cloneNode(true) is cheaper than rebuilding the three-node tree each time.
    wrapper.appendChild(_makeDecryptingBadge());
  } else if (typeof plaintext === 'object') {
    // Tagged status notice from _status().
    wrapper.appendChild(_makeStatusBadge(plaintext.status, plaintext.icon, plaintext.danger));
  } else {
    // Cap at MAX_INLINE_MESSAGE_CHARS — senders already enforce this, but guard anyway
    // to prevent runaway DOM growth from crafted messages.
    if (plaintext.length > MAX_INLINE_MESSAGE_CHARS) {
      console.info('[age] message truncated for display: %d of %d characters shown', MAX_INLINE_MESSAGE_CHARS, plaintext.length);
    }
    const displayText = plaintext.length > MAX_INLINE_MESSAGE_CHARS ? plaintext.slice(0, MAX_INLINE_MESSAGE_CHARS) : plaintext;
    const emojiSize = isJumboEmoji(displayText) ? 48 : 22;
    renderBlockContent(wrapper, displayText, true, emojiSize);
  }

  // Prefer the explicit insertAfter anchor, then fall back to after
  // message-content- (the li's own text body), then append to the li.
  if (insertAfter?.parentElement) {
    insertAfter.parentElement.insertBefore(wrapper, insertAfter.nextSibling);
  } else {
    // The li's own text body is the first [id^="message-content-"] in DOM order. Reply
    // references do not get one; a forwarded message has a second, same-id element
    // inside its forward container, which comes later.
    const contentEl = liElement.querySelector('[id^="message-content-"]');
    if (contentEl?.parentElement) {
      contentEl.parentElement.insertBefore(wrapper, contentEl.nextSibling);
    } else {
      liElement.appendChild(wrapper);
    }
  }
}

// ─── Placeholder display ──────────────────────────────────────────────────────

// showAgePlaceholder(li, reason): hides .age attachments, clears render
// wrappers, and inserts a status badge.

// showAllPlaceholders(reason): updates all visible chat items.
// Called on RELOCK, globalOn=false, and initial locked load.

// reason:
//   'locked'   → Extension locked.
//   'disabled' → Decryption disabled.

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
    ? _status('Decryption disabled.', 'lock-open')
    : _status('Extension locked.', 'lock');

  renderDecryptedMessage(li, text, undefined, lastAnchor);
}

function showAllPlaceholders(reason) {
  document.querySelectorAll('li[id^="chat-messages-"]')
    .forEach(li => showAgePlaceholder(li, reason));
  showQuotedPlaceholders(reason);
}

// Scans message li for encrypted attachments.

// Centralizes Discord attachment selectors for easy updates.
const FILE_LINK_SEL =
  'a[href^="https://cdn.discordapp.com/attachments/"]' +
  '[rel="noreferrer noopener"]:not([aria-label])';

// Checks for attachId within root; compare in JS because CSS.escape() replaces NUL
// with U+FFFD. Each root contains at most a few wrappers.

function _rootShowsSlot(root, attachId) {
  for (const el of root.querySelectorAll('[data-age-msg-slot]')) {
    if (el.dataset.ageMsgSlot === attachId) return true;
  }
  return false;
}

// Shared encrypted attachment scanner.

// Keys tasks by attachId and DOM root to handle virtualized reinsertions.
// Quoted scans additionally check processed/in-flight state before dispatch.
function _scanForEncryptedAttachments(root, keyFn, { checkExtraGuards = false } = {}) {
  const nameLinks = root.querySelectorAll(FILE_LINK_SEL);
  for (const nameEl of nameLinks) {
    const rawName = nameEl.textContent?.trim() ?? '';
    if (!rawName.endsWith('.age')) continue;

    const cdnUrl = nameEl.href;
    if (!cdnUrl) continue;

    const attachId = keyFn(cdnUrl);
    const _previousRoot = _attachmentInProgress.get(attachId);
    if (checkExtraGuards) {
      // Id-less roots share an attachId per URL, including across remounts.
      // Keep processed/in-flight guards per root; skip only if THIS root has the result
      // or task. Other roots call processEncryptedAttachment to use the cache or await
      // the existing task via _awaitStaleInFlight, then render locally.

      if (_processedIds.has(attachId) && _rootShowsSlot(root, attachId)) continue;
      if (_inFlight.has(attachId) && _previousRoot === root) continue;
    }
    if (_previousRoot === root) continue;

    // Resolved after the guards (they only depend on attachId) but BEFORE the
    // _attachmentInProgress.set below: a missing card must not leave a stale entry.
    const fileCard = nameEl.closest('div[class*="file_"]');
    if (!fileCard) continue;

    _attachmentInProgress.set(attachId, root);

    processEncryptedAttachment(root, fileCard, cdnUrl, rawName, _previousRoot).catch(e => {
      _attachmentInProgress.delete(attachId);
      console.error('[age] attachment task failed:', e?.message ?? e);
    });
  }
}

function processAttachmentsInLi(li) {
  _scanForEncryptedAttachments(li, cdnUrl => _attachId(li, cdnUrl));
}

// Processes a single quotedChatMessage container from the hot MutationObserver
// path in attachMsgObserver(). Mirrors the per-container loop in
// processQuotedMessages() for only the containers in the current mutation batch.
function _processQuotedContainer(container) {
  if (canDecrypt()) {
    _scanForEncryptedAttachments(container, cdnUrl => _attachId(container, cdnUrl), { checkExtraGuards: true });
  } else {
    showQuotedPlaceholder(container, _lockReason());
  }
}

// Scans quoted message containers missed by li-based attachment processing.

// Uses CDN URL signatures and synthetic ids for stable deduplication.
function processQuotedMessages() {
  if (!canDecrypt()) return;
  const containers = document.querySelectorAll(ID_LESS_ROOT_SEL);
  for (const container of containers) {
    _scanForEncryptedAttachments(container, cdnUrl => _attachId(container, cdnUrl), { checkExtraGuards: true });
  }
}

// Called from attachMsgObserver and scanExisting.
function processLiFull(li) {
  if (canDecrypt()) processAttachmentsInLi(li);
}

// ─── Init ────────────────────────────────────────────────────────────────────

// DOM-dependent setup. The message channels below deliberately live outside this function.
async function init() {
  startNavObserver();
  waitForMessageList();
}

// Warms the bridge iframe and workers so the first decrypt pays no cold-start penalty. Only
// done for a session that can decrypt, and only after the page has loaded and gone idle:
// a locked or disabled session never uses them, and spawning them during page load
// competes with first paint and the app's own boot.
let _warmUpScheduled = false;
function scheduleWarmUp() {
  if (_warmUpScheduled) return;
  _warmUpScheduled = true;
  const run = () => { _warmUpScheduled = false; if (canDecrypt()) warmUpCrypto(); };
  const idle = () => (typeof requestIdleCallback === 'function'
    ? requestIdleCallback(run, { timeout: 2000 }) : setTimeout(run, 0));
  if (document.readyState === 'complete') idle();
  else window.addEventListener('load', idle, { once: true });
}

function warmUpCrypto() {
  getFetchIframe();
  getTextWorker();   // never terminated
  getMediaWorker();  // terminated on nav, recreated lazily
}

// Set up the DOM-free bridge at top level before the interceptor can post.
// Order is critical:
// 1. Register listeners first.
// 2. Relay state once before the unlock pull, preventing a stale "locked"
//    relay from overwriting a payload that arrives first.
// 3. Pull unlock state; upload handlers await this via _awaitBootUnlock.
listenForMessages();
relayInterceptorState(!!_session?.mldsaSeedBytes);
_bootUnlock = requestUnlock();
listenForInterceptorMessages();

if (document.body) {
  init().catch(e => console.error('[age] init error:', e));
} else {
  document.addEventListener('DOMContentLoaded', () => init().catch(e => console.error('[age] init error:', e)));
}
})();
