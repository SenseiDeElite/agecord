/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// upload-interceptor.js — Agecord

'use strict';

function err(...a)  { console.error('[age-intercept]', ...a); }

// ─── Lock state ───────────────────────────────────────────────────────────────

let _locked = true;
// Set by content.js via AGE_INTERCEPTOR_STATE. When false, uploads pass through
// unmodified — no recipient configured, so interception would only discard files.
let _activeEntry = false;
Object.defineProperty(window, '__ageLocked', { get: () => _locked, configurable: true });

// ─── Constants ────────────────────────────────────────────────────────────────

// Walk limit of 10 visits steps 0–9 (loop condition: steps < limit).
// Exactly 10 prevents a stale fiber from a second open edit-box being returned.
const SLATE_FIBER_WALK_LIMIT = 10;

// ─── Channel / thread path patterns ────────────────────────────────────────────

// Channel/thread route patterns.
// Keep id constraints aligned with content.js.
// Channel allows DM routes; threads require guild ids.
const THREAD_PATH_PATTERN = new URLPattern({
  pathname: '/channels/:guildId(\\d+)/:channelId(\\d+)/threads/:threadId(\\d+){/*}?',
});
const CHANNEL_PATH_PATTERN = new URLPattern({
  pathname: '/channels/:guildId/:channelId(\\d+){/*}?',
});

// ─── Attachment-pending guard ─────────────────────────────────────────────────

// Blocks all attachment entry-points until the upload tray clears or the
// 8-second safety timeout fires.
let _attachmentPending = false;

// ─── postMessage round-trip ───────────────────────────────────────────────────

const _pending = new Map();
let _nextId = 0;

window.addEventListener('message', (e) => {
  if (e.source !== window) return;
  const { type, requestId } = e.data ?? {};

  if (type === 'AGE_ENCRYPT_FILE_ACK' && _pending.has(requestId)) {
    const entry = _pending.get(requestId);
    entry.onAck?.();
  }

  if (type === 'AGE_ENCRYPT_FILE_RESULT' && _pending.has(requestId)) {
    const { resolve, reject, fileName } = _pending.get(requestId);
    _pending.delete(requestId);
    if (e.data.error) {
      err('encrypt FAILED requestId=%s fileName=%s —', requestId, fileName, e.data.error);
      reject(new Error(e.data.error));
    } else {
      resolve({ buffer: e.data.buffer, encryptedName: e.data.encryptedName });
    }
  }

  // ── AGE_ENCRYPT_TEXT_MESSAGE ─────────────────────────────────────────────────
  
  // Same round-trip shape as AGE_ENCRYPT_FILE, but content.js runs the message
  // (compress+sign) pipeline instead of the generic file pipeline — used so a
  // long paste can be sent as message.txt.age, identical to a typed send.
  if (type === 'AGE_ENCRYPT_TEXT_MESSAGE_ACK' && _pending.has(requestId)) {
    const entry = _pending.get(requestId);
    entry.onAck?.();
  }

  if (type === 'AGE_ENCRYPT_TEXT_MESSAGE_RESULT' && _pending.has(requestId)) {
    const { resolve, reject } = _pending.get(requestId);
    _pending.delete(requestId);
    if (e.data.error) {
      err('encrypt text message FAILED requestId=%s —', requestId, e.data.error);
      reject(new Error(e.data.error));
    } else {
      resolve(e.data.buffer);
    }
  }

  if (type === 'AGE_INTERCEPTOR_STATE') {
    _locked = !e.data.unlocked;
    _activeEntry = !!e.data.activeEntry;
  }

  // Triggers upload preview via React onChange.
  // Avoids DOM events and async bypass handling issues.
  if (type === 'AGE_DO_UPLOAD') {
    try {
      uploadSignedMessageBytes(e.data.buffer);
      window.postMessage({ type: 'AGE_DO_UPLOAD_RESULT', ok: true }, '*');
    } catch (uploadErr) {
      err('AGE_DO_UPLOAD failed:', uploadErr.message);
      window.postMessage({ type: 'AGE_DO_UPLOAD_RESULT', ok: false, error: uploadErr.message }, '*');
    }
  }

  // ── AGE_UPLOAD_TEXT_AS_FILE ──────────────────────────────────────────────────
  
  // content.js can't reach React's onChange itself (page-context only) — asks us
  // to attach `text` as a generic encrypted file when it's too long for a single
  // encrypted message (mirrors the paste handler's own >4000-char branch below).
  if (type === 'AGE_UPLOAD_TEXT_AS_FILE') {
    const { text, channelId: uploadChannelId, guildId: uploadGuildId } = e.data;
    (async () => {
      try {
        const file = new File([text], 'message.txt', { type: 'text/plain' });
        await deliverEncryptedFiles([file], uploadChannelId, uploadGuildId);
        window.postMessage({ type: 'AGE_UPLOAD_TEXT_AS_FILE_RESULT', requestId, ok: true }, '*');
      } catch (uploadErr) {
        err('AGE_UPLOAD_TEXT_AS_FILE failed:', uploadErr.message);
        window.postMessage({ type: 'AGE_UPLOAD_TEXT_AS_FILE_RESULT', requestId, ok: false, error: uploadErr.message }, '*');
      }
    })();
  }

  if (type === 'AGE_ATTACHMENT_CLEARED') {
    _attachmentPending = false;
  }

  // 800 ms delay prevents a reload loop on extension uninstall.
  if (type === 'AGE_CONTEXT_INVALIDATED') {
    setTimeout(() => location.reload(), 800);
  }

  if (type === 'AGE_CLEAR_TEXTBOX') {
    const nonce = e.data?.nonce;
    const ok = clearSlateTextbox();
    window.postMessage(
      ok ? { type: 'AGE_CLEAR_TEXTBOX_RESULT', ok: true,  nonce }
         : { type: 'AGE_CLEAR_TEXTBOX_RESULT', ok: false, nonce, error: 'clearSlateTextbox failed' },
      '*'
    );
  }

  // ── AGE_GET_SLATE_TEXT ──────────────────────────────────────────────────────
  
  // Must run in page context: the isolated world gets a proxy of the React
  // fiber heap, not the live instance.
  // Custom emoji <img> nodes are serialised as [name](url) markdown.
  if (type === 'AGE_GET_SLATE_TEXT') {
    const nonce = e.data?.nonce;
    const tb = getMainTextbox();
    if (!tb) throw new Error('Slate textbox not found');

    const lines = [];
    for (const block of tb.children) {
      // Blockquote blocks render the ">" prefix as DOM structure, not text.
      // Detect by class substring and prepend it manually after extraction.
      const isBlockquote =
        (typeof block.className === 'string' && block.className.includes('blockquoteContainer')) ||
        (block.firstElementChild &&
         typeof block.firstElementChild.className === 'string' &&
         block.firstElementChild.className.includes('blockquoteContainer'));

      let lineText = '';
      const walker = document.createTreeWalker(
        block,
        NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
        {
          acceptNode(node) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Reject aria companion spans — they duplicate emoji names for
              // screen readers and must not appear in serialised plaintext.
              const cls = node.className;
              if (typeof cls === 'string' && cls.includes('hiddenVisually'))
                return NodeFilter.FILTER_REJECT;
              if (node.tagName === 'IMG') return NodeFilter.FILTER_ACCEPT;
              // Detect Slate void elements via data-slate-void. Processed in the walk below.
              if (node.dataset?.slateVoid === 'true') return NodeFilter.FILTER_ACCEPT;
              return NodeFilter.FILTER_SKIP;
            }
            return NodeFilter.FILTER_ACCEPT;
          }
        }
      );

      let node;
      // Set when a void node's source has been reconstructed from its Slate
      // element, so we skip re-emitting its rendered display text from the
      // descendant text nodes the walker would otherwise still visit.
      let voidBoundary = null;
      while ((node = walker.nextNode()) !== null) {
        if (voidBoundary) {
          if (voidBoundary.contains(node)) continue;
          voidBoundary = null;
        }

        if (node.nodeType === Node.TEXT_NODE) {
          lineText += node.textContent;
        } else if (node.nodeType === Node.ELEMENT_NODE &&
                   node.dataset?.slateVoid === 'true') {
          const src = _resolveVoidNodeSource(node);
          if (src !== null) {
            lineText += src;
            voidBoundary = node;
          }
          // null = non-time void; descend and emit rendered text.
        } else if (node.tagName === 'IMG' &&
                   node.dataset.type === 'emoji' &&
                   node.dataset.id) {
          // Custom emoji. Validate before embedding into URL/markdown.
          // emojiId: Discord snowflake (digits, 17–20 chars).
          // emojiName: word chars and hyphens, max 100 chars.
          const rawId   = String(node.dataset.id);
          const altText = node.alt ?? '';
          const rawName = altText.replace(/^:|:$/g, '');

          const emojiId   = /^\d{17,20}$/.test(rawId) ? rawId : null;
          const emojiName = /^[\w-]{1,100}$/.test(rawName) ? rawName : null;

          if (!emojiId || !emojiName) {
            lineText += altText || `:${rawId}:`;
          } else {
            const isAnimated = typeof node.src === 'string' &&
                               node.src.includes('animated=true');
            const emojiUrl = isAnimated
              ? `https://cdn.discordapp.com/emojis/${emojiId}.webp?size=48&animated=true&name=${emojiName}&lossless=true`
              : `https://cdn.discordapp.com/emojis/${emojiId}.webp?size=48&name=${emojiName}&lossless=true`;
            lineText += `[${emojiName}](${emojiUrl})`;
          }
        } else if (node.tagName === 'IMG' && node.dataset.type === 'emoji') {
          // Standard Unicode emoji rendered as <img> — alt is the raw codepoint(s).
          const alt = node.alt ?? '';
          if (alt) lineText += alt;
        }
      }

      // Slate appends a structural trailing newline to every block's last leaf.
      const serialised = lineText.replace(/\n+$/, '');
      lines.push(isBlockquote ? '> ' + serialised : serialised);
    }

    const text = lines.join('\n').trim() ||
                 (tb.innerText?.trim() ?? '');

    window.postMessage({ type: 'AGE_GET_SLATE_TEXT_RESULT', ok: true, text, nonce }, '*');
  }
});

// Walks a DOM element's React fiber chain (fiber.return) up to
// SLATE_FIBER_WALK_LIMIT steps. matchFn(fiber) returns undefined to keep
// walking, or anything else to stop and return that value.
function walkFiberUp(el, matchFn) {
  const fiberKey = Object.keys(el).find(k => k.startsWith('__reactFiber$'));
  if (!fiberKey) return undefined;

  let fiber = el[fiberKey];
  for (let steps = 0; fiber && steps < SLATE_FIBER_WALK_LIMIT; steps++, fiber = fiber.return) {
    const result = matchFn(fiber);
    if (result !== undefined) return result;
  }
  return undefined;
}

// Returns source <t:UNIX:STYLE> tag for timestamp voids.
// Non-timestamp voids return null; invalid structure throws.
function _resolveVoidNodeSource(el) {
  const result = walkFiberUp(el, (fiber) => {
    const element = fiber.memoizedProps?.element;
    if (!element || typeof element !== 'object') return undefined;
    if (element.type !== 'timestamp') return null;

    const parsed = element.parsed;
    const original = parsed?.originalMatch?.[0];
    if (typeof original === 'string' && /^<t:\d+(?::[RfFtTdDSs])?>$/.test(original)) {
      return original;
    }

    const unix = parseInt(parsed?.timestamp, 10);
    if (!Number.isNaN(unix)) {
      const style = typeof parsed?.format === 'string' ? parsed.format : 'f';
      return `<t:${unix}:${style}>`;
    }

    throw new Error('Timestamp element.parsed has an unrecognized shape.');
  });

  if (result === undefined) throw new Error('No Slate element prop found within fiber walk limit.');
  return result;
}

// ─── Slate textbox clear ──────────────────────────────────────────────────────

// Must run in page context: the isolated world gets a fiber proxy, not the live
// instance, and Slate's beforeinput handler rejects synthetic (non-trusted) events.
function getMainTextbox() {
  const all = [...document.querySelectorAll('[data-slate-editor="true"]')];
  const composers = all.filter(el =>
    el.closest('form') && !el.closest('li[id^="chat-messages-"]'));

  // In split view, prefer the composer containing the focused element.
  if (composers.length > 1) {
    const active = document.activeElement;
    if (active) {
      const exact = composers.find(c => c === active);
      if (exact) return exact;
      const ancestor = composers.find(c => c.contains(active));
      if (ancestor) return ancestor;
    }
  }

  if (composers.length > 0) return composers[0];
  const nonEdit = all.find(el => !el.closest('li[id^="chat-messages-"]'));
  return nonEdit ?? all[0] ?? null;
}

// Resolves active composer route at capture time.
// Returns ids together to avoid post-await route races.
function getInterceptorLocation() {
  // Determine whether the active composer is inside MAIN or SECTION so we
  // can pick the right ID in split thread view.
  const active = document.activeElement;
  let composerRole = null;
  if (active) {
    let el = active;
    while (el && el !== document.body) {
      const tag = el.tagName;
      if (tag === 'MAIN') { composerRole = 'MAIN'; break; }
      if (tag === 'SECTION') { composerRole = 'SECTION'; break; }
      el = el.parentElement;
    }
  }

  const threadMatch = THREAD_PATH_PATTERN.exec(location.href);
  if (threadMatch) {
    const { guildId, channelId, threadId } = threadMatch.pathname.groups;
    // SECTION maps to thread composer; otherwise use parent channel.
    // Matches content.js channel resolution behavior.
    return { channelId: composerRole === 'SECTION' ? threadId : channelId, guildId };
  }

  const chanMatch = CHANNEL_PATH_PATTERN.exec(location.href);
  if (chanMatch) {
    const { guildId, channelId } = chanMatch.pathname.groups;
    return { channelId, guildId };
  }

  return { channelId: null, guildId: null };
}

function clearSlateTextbox() {
  try {
    const tb = getMainTextbox();
    if (!tb) throw new Error('Slate textbox not found');

    const editor = walkFiberUp(tb, (fiber) => {
      const p = fiber.memoizedProps;
      if (p && p.editor && Array.isArray(p.editor.children) && typeof p.editor.apply === 'function') {
        return p.editor;
      }
      return undefined;
    });
    if (!editor) throw new Error('Slate editor not found in fiber chain');

    const children = editor.children;
    if (!children || children.length === 0) return true;

    function lastLeaf(nodes, path) {
      const last = nodes[nodes.length - 1];
      if (!last) return [path, 0];
      if (typeof last.text === 'string') return [[...path, nodes.length - 1], last.text.length];
      return lastLeaf(last.children, [...path, nodes.length - 1]);
    }
    const [focusPath, focusOffset] = lastLeaf(children, []);
    editor.selection = {
      anchor: { path: [0, 0], offset: 0 },
      focus:  { path: focusPath, offset: focusOffset },
    };

    editor.deleteFragment();

    try {
      editor.selection = { anchor: { path: [0, 0], offset: 0 }, focus: { path: [0, 0], offset: 0 } };
    } catch (_) {}

    return true;
  } catch (e) {
    err('clearSlateTextbox failed:', e?.message ?? e);
    return false;
  }
}

// Sends file bytes to content.js → file-crypto-worker.js for encryption and signing.
// channelId is resolved synchronously by the caller at capture time and included
// so content.js can build the correct sig prefix in split-view thread composers.
const ACK_TIMEOUT_MS    = 2_000;
const ENCRYPT_TIMEOUT_MS = 20_000;

// Tracks postMessage requests with ACK/result phases.
// Stores extra fields for response handling.
function withPendingRequest(buildPayload, extraEntryFields = {}) {
  const { fileName } = extraEntryFields;
  const label = fileName ? ` fileName=${fileName}` : '';

  return new Promise((resolve, reject) => {
    const requestId = String(_nextId++);
    let ackTimer    = null;
    let resultTimer = null;

    function cleanup() {
      clearTimeout(ackTimer);
      clearTimeout(resultTimer);
      _pending.delete(requestId);
    }

    ackTimer = setTimeout(() => {
      if (_pending.has(requestId)) {
        cleanup();
        err('encrypt ACK timeout after %sms requestId=%s%s — content script may be unavailable',
          ACK_TIMEOUT_MS, requestId, label);
        reject(new Error('Encryption unavailable — please reload the Discord tab and try again.'));
      }
    }, ACK_TIMEOUT_MS);

    _pending.set(requestId, {
      ...extraEntryFields,
      onAck: () => {
        clearTimeout(ackTimer);
        resultTimer = setTimeout(() => {
          if (_pending.has(requestId)) {
            cleanup();
            err('encrypt timeout after %sms requestId=%s%s', ENCRYPT_TIMEOUT_MS, requestId, label);
            reject(new Error(fileName ? `Encryption timeout for "${fileName}"` : 'Encryption timeout'));
          }
        }, ENCRYPT_TIMEOUT_MS);
      },
      resolve: (v) => { cleanup(); resolve(v); },
      reject:  (e) => { cleanup(); reject(e);  },
    });

    buildPayload(requestId);
  });
}

function encryptFile(fileName, buffer, channelId, guildId) {
  return withPendingRequest(
    (requestId) => {
      window.postMessage(
        { type: 'AGE_ENCRYPT_FILE', requestId, fileName, buffer, channelId, guildId },
        '*',
        [buffer]
      );
    },
    { fileName }
  );
}

// Encryption failures abort; no plaintext fallback.
// Route ids are captured before await and forwarded unchanged.
async function encryptFileList(files, channelId, guildId) {
  const dt = new DataTransfer();
  for (const file of files) {
    if (file.name.endsWith('.age')) {
      dt.items.add(file);
      continue;
    }
    const plainBuffer = await file.arrayBuffer();
    const { buffer: encBuffer, encryptedName } = await encryptFile(file.name, plainBuffer, channelId, guildId);
    dt.items.add(new File([encBuffer], encryptedName, { type: 'application/octet-stream' }));
  }
  return dt;
}

// Hands a DataTransfer's files to React's onChange and starts tray tracking.
// Shared tail for every upload path (drop, change, paste, AGE_DO_UPLOAD, ...).
function deliverFileList(dt) {
  const onChange = getFileInputOnChange();
  onChange({ currentTarget: { files: dt.files, err: null } });
  _attachmentPending = true;
  watchTrayAndClearPending();
}

// Encrypts files and delivers them in one step — the common case for every
// upload entry point below.
async function deliverEncryptedFiles(files, channelId, guildId) {
  deliverFileList(await encryptFileList(files, channelId, guildId));
}

// Clears a stale _attachmentPending flag left behind by a drop whose tray
// never appeared. Not used by the drop handler itself — see its own comment.
function clearStalePending() {
  if (!_attachmentPending) return;
  _attachmentPending = false;
  window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, '*');
}

// Signs text through content.js pipeline.
// Returns signed AGE bytes; no plaintext fallback.
function encryptTextMessage(text, channelId, guildId) {
  return withPendingRequest((requestId) => {
    window.postMessage({ type: 'AGE_ENCRYPT_TEXT_MESSAGE', requestId, text, channelId, guildId }, '*');
  });
}

// Wraps already-signed age bytes as message.txt.age and hands them to React's
// onChange, identical to what AGE_DO_UPLOAD and the paste handler both need —
// factored out so neither has to duplicate the DataTransfer/File plumbing.
function uploadSignedMessageBytes(buffer) {
  const file = new File([buffer], 'message.txt.age', { type: 'application/octet-stream' });
  const dt   = new DataTransfer();
  dt.items.add(file);
  deliverFileList(dt);
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

// Returns React's onChange from the file input closest to the active composer.
// Throws if the input or its React props are missing.
function getFileInputOnChange() {
  const activeTb   = getMainTextbox();
  const activeForm = activeTb?.closest('form');
  const input = (activeForm?.querySelector('input[type="file"]'))
             ?? document.querySelector('input[type="file"]');
  if (!input) throw new Error('file input not found');

  const propsKey = Object.keys(input).find(k => k.startsWith('__reactProps'));
  if (!propsKey) throw new Error('React props not found on file input');

  const onChange = input[propsKey].onChange;
  if (typeof onChange !== 'function') throw new Error('onChange not a function');
  return onChange;
}

// Watches for the attachment tray and clears _attachmentPending once it's gone
// (or immediately after 600 ms if no tray appears — DM / no-tray path).
// An 8-second hard timeout guards against a stuck tray.
function watchTrayAndClearPending() {
  const TRAY_SEL = 'ul[data-list-id="attachments"]';

  let fired = false;
  function clearOnce() {
    if (fired) return;
    fired = true;
    trayAppearObserver.disconnect();
    _attachmentPending = false;
    window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, '*');
  }

  function watchForTrayGone() {
    const trayGoneObserver = new MutationObserver(() => {
      if (!document.querySelector(TRAY_SEL)) {
        trayGoneObserver.disconnect();
        clearOnce();
      }
    });
    trayGoneObserver.observe(document.body, { childList: true, subtree: true });
  }

  const trayAppearObserver = new MutationObserver(() => {
    if (document.querySelector(TRAY_SEL)) {
      trayAppearObserver.disconnect();
      watchForTrayGone();
    }
  });

  if (document.querySelector(TRAY_SEL)) {
    watchForTrayGone();
  } else {
    trayAppearObserver.observe(document.body, { childList: true, subtree: true });
    setTimeout(() => clearOnce(), 600);
  }

  setTimeout(() => clearOnce(), 8_000);
}

// ─── dragover (window) ────────────────────────────────────────────────────────

window.addEventListener('dragover', (e) => {
  if (_locked || !_activeEntry) return;
  if (!(e.dataTransfer?.types ?? []).includes('Files')) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
}, true);

// ─── drop (window) ────────────────────────────────────────────────────────────

// Window capture required; Discord blocks document capture.
// Uses React onChange because synthetic drag events are rejected.
window.addEventListener('drop', async (e) => {
  if (_locked || !_activeEntry) return;
  const files = [...(e.dataTransfer?.files ?? [])];
  if (files.length === 0) return;

  // Resolve channelId/guildId synchronously — activeElement (and location.href's
  // relevance to it) is unreliable after any await.
  const { channelId, guildId } = getInterceptorLocation();

  // Stop unconditionally BEFORE the _attachmentPending check. Returning early
  // without stopping lets the trusted drop fall through to Discord raw.
  e.stopImmediatePropagation();
  e.preventDefault();

  if (_attachmentPending) return;

  try {
    await deliverEncryptedFiles(files, channelId, guildId);
  } catch (dropErr) {
    err('drop: failed — %s', dropErr?.message ?? dropErr);
  }
}, true);

// ─── change (file picker) ─────────────────────────────────────────────────────

// Call React onChange directly. Dispatching a synthetic 'change'
// would re-enter this capture listener, clear the files override, and swallow
// the upload before Discord's handler. Direct invocation avoids recursion.
document.addEventListener('change', async (e) => {
  if (_locked || !_activeEntry) return;
  const input = e.target;
  if (input?.type !== 'file') return;

  // Delete any leftover override before reading so we get the real selection.
  try { delete input.files; } catch { /* non-configurable — already native */ }
  const files = [...(input.files ?? [])];
  if (files.length === 0) return;

  const { channelId, guildId } = getInterceptorLocation();

  // Stop unconditionally — same reason as drop.
  e.stopImmediatePropagation();
  e.preventDefault();

  // File-picker is an explicit user action. A stale pending flag means the
  // prior drop's tray silently never appeared. Reset rather than discarding.
  clearStalePending();

  try {
    await deliverEncryptedFiles(files, channelId, guildId);
  } catch (changeErr) {
    err('change: failed — %s', changeErr?.message ?? changeErr);
  }
}, true);

// ─── paste ────────────────────────────────────────────────────────────────────

// Firefox lacks clipboardData on synthetic events; call onChange directly.
// Intercepts pasted text before Discord creates message.txt.
// Limits match Discord message handling thresholds.
const NATIVE_PASTE_FILE_THRESHOLD = 2000;
const MESSAGE_TEXT_MAX_CHARS      = 4000;

document.addEventListener('paste', async (e) => {
  if (_locked || !_activeEntry) return;
  const files = [...(e.clipboardData?.files ?? [])];
  const text  = files.length === 0 ? (e.clipboardData?.getData('text/plain') ?? '') : '';

  const needsInterception = files.length > 0 || text.length > NATIVE_PASTE_FILE_THRESHOLD;
  if (!needsInterception) return;

  const { channelId, guildId } = getInterceptorLocation();

  e.stopImmediatePropagation();
  e.preventDefault();

  clearStalePending();

  try {
    if (files.length > 0) {
      await deliverEncryptedFiles(files, channelId, guildId);
    } else if (text.length <= MESSAGE_TEXT_MAX_CHARS) {
      // Fits in a single encrypted message — encrypt with the same
      // compress+sign pipeline a typed send uses, producing message.txt.age.
      const buffer = await encryptTextMessage(text, channelId, guildId);
      uploadSignedMessageBytes(buffer);
    } else {
      // Too long for a single encrypted message — attach the full,
      // untruncated text as a real encrypted file instead.
      const textFile = new File([text], 'message.txt', { type: 'text/plain' });
      await deliverEncryptedFiles([textFile], channelId, guildId);
    }
  } catch (pasteErr) {
    err('paste: failed — %s', pasteErr?.message ?? pasteErr);
  }
}, true);
