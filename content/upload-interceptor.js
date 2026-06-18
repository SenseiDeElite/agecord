// upload-interceptor.js — Discord Age Encryption

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
let _redispatching = false;

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

  if (type === 'AGE_INTERCEPTOR_STATE') {
    _locked = !e.data.unlocked;
    _activeEntry = !!e.data.activeEntry;
  }

  // ── AGE_DO_UPLOAD ───────────────────────────────────────────────────────────
  // Calls React's onChange prop directly to trigger Discord's upload preview.
  // Bypasses the DOM event entirely — our capture listener would otherwise
  // catch any re-dispatched 'change', and a postMessage bypass flag arrives
  // asynchronously, after the synchronous dispatchEvent chain completes.
  if (type === 'AGE_DO_UPLOAD') {
    try {
      // In split view, use the input from the active composer's form so the
      // upload is routed to the correct channel.
      const onChange = getFileInputOnChange();

      const file = new File([e.data.buffer], 'message.txt.age', { type: 'application/octet-stream' });
      const dt   = new DataTransfer();
      dt.items.add(file);

      // Discord's handler only reads e.currentTarget.files and e.currentTarget.err.
      onChange({ currentTarget: { files: dt.files, err: null } });

      _attachmentPending = true;
      watchTrayAndClearPending();
      window.postMessage({ type: 'AGE_DO_UPLOAD_RESULT', ok: true }, '*');

    } catch (uploadErr) {
      err('AGE_DO_UPLOAD failed:', uploadErr.message);
      window.postMessage({ type: 'AGE_DO_UPLOAD_RESULT', ok: false, error: uploadErr.message }, '*');
    }
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
  // Vencord custom emoji <img> nodes are serialised as [name](url) markdown.
  if (type === 'AGE_GET_SLATE_TEXT') {
    const nonce = e.data?.nonce;
    try {
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
                return NodeFilter.FILTER_SKIP;
              }
              return NodeFilter.FILTER_ACCEPT;
            }
          }
        );

        let node;
        while ((node = walker.nextNode()) !== null) {
          if (node.nodeType === Node.TEXT_NODE) {
            lineText += node.textContent;
          } else if (node.tagName === 'IMG' &&
                     node.dataset.type === 'emoji' &&
                     node.dataset.id) {
            // Custom/Nitro emoji. Validate before embedding into URL/markdown.
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
    } catch (e2) {
      const fallback = getMainTextbox()?.innerText?.trim() ?? '';
      window.postMessage({ type: 'AGE_GET_SLATE_TEXT_RESULT', ok: true, text: fallback, nonce }, '*');
    }
  }
});

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

// Resolves the channel ID for the active composer synchronously.
// Must be called at event-capture time before any await — activeElement is
// unreliable after suspension.
// Returns null for forum modals and unrecognised paths; content.js aborts
// encryption in that case.
function getInterceptorChannelId() {
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

  const path = location.pathname;

  // Split thread view: MAIN=parent channel, SECTION=thread panel.
  const threadMatch = path.match(/^\/channels\/([^/]+)\/([^/]+)\/threads\/([^/]+)/);
  if (threadMatch) {
    return composerRole === 'MAIN' ? threadMatch[2] : threadMatch[3];
  }

  const chanMatch = path.match(/^\/channels\/([^/]+)\/([^/]+)(?:\/|$)/);
  if (chanMatch) return chanMatch[2];

  return null;
}

function clearSlateTextbox() {
  try {
    const tb = getMainTextbox();
    if (!tb) throw new Error('Slate textbox not found');

    const fiberKey = Object.keys(tb).find(k => k.startsWith('__reactFiber$'));
    if (!fiberKey) throw new Error('No React fiber on textbox');

    let fiber = tb[fiberKey];
    let editor = null;
    for (let steps = 0; fiber && steps < SLATE_FIBER_WALK_LIMIT; steps++, fiber = fiber.return) {
      const p = fiber.memoizedProps;
      if (p && p.editor &&
          Array.isArray(p.editor.children) &&
          typeof p.editor.apply === 'function') {
        editor = p.editor;
        break;
      }
    }
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

    if (typeof editor.deleteFragment === 'function') {
      editor.deleteFragment();
    } else {
      for (let i = children.length - 1; i >= 1; i--) {
        try { editor.apply({ type: 'remove_node', path: [i], node: children[i] }); } catch (_) {}
      }
      try { editor.apply({ type: 'remove_node', path: [0], node: children[0] }); } catch (_) {}
      try { editor.apply({ type: 'insert_node', path: [0], node: { type: 'paragraph', children: [{ text: '' }] } }); } catch (_) {}
    }

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
//
// Two-phase timeout:
const ACK_TIMEOUT_MS    = 10_000;
const ENCRYPT_TIMEOUT_MS = 5 * 60 * 1000;

function encryptFile(fileName, buffer, channelId) {
  return new Promise((resolve, reject) => {
    const requestId = String(_nextId++);
    const t0 = performance.now();

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
        err('encrypt ACK timeout after %sms requestId=%s fileName=%s — content script may be unavailable',
          ACK_TIMEOUT_MS, requestId, fileName);
        reject(new Error(`Encryption unavailable — please reload the Discord tab and try again.`));
      }
    }, ACK_TIMEOUT_MS);

    _pending.set(requestId, {
      onAck: () => {
        clearTimeout(ackTimer);
        resultTimer = setTimeout(() => {
          if (_pending.has(requestId)) {
            cleanup();
            err('encrypt timeout after %sms requestId=%s fileName=%s', ENCRYPT_TIMEOUT_MS, requestId, fileName);
            reject(new Error(`AGE_ENCRYPT_FILE timeout for "${fileName}"`));
          }
        }, ENCRYPT_TIMEOUT_MS);
      },
      resolve: (v) => { cleanup(); resolve(v); },
      reject:  (e) => { cleanup(); reject(e);  },
      t0,
      fileName,
    });

    window.postMessage(
      { type: 'AGE_ENCRYPT_FILE', requestId, fileName, buffer, channelId },
      '*',
      [buffer]
    );
  });
}

// Throws on encryption failure — callers must not fall back to plaintext.
async function encryptFileList(files, channelId) {
  const dt = new DataTransfer();
  for (const file of files) {
    if (file.name.endsWith('.age')) {
      dt.items.add(file);
      continue;
    }
    const plainBuffer = await file.arrayBuffer();
    const { buffer: encBuffer, encryptedName } = await encryptFile(file.name, plainBuffer, channelId);
    dt.items.add(new File([encBuffer], encryptedName, { type: 'application/octet-stream' }));
  }
  return dt;
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
  if (_locked || !_activeEntry || _redispatching) return;
  if (!(e.dataTransfer?.types ?? []).includes('Files')) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
}, true);

// ─── drop (window) ────────────────────────────────────────────────────────────
// Must be on WINDOW capture: Discord's uploadArea calls stopImmediatePropagation()
// in its own capture listener before the event reaches document.
// Delivery via React onChange prop — synthetic DragEvents have effectAllowed='none'
// and are silently rejected by Discord's handler.
window.addEventListener('drop', async (e) => {
  if (_locked || !_activeEntry || _redispatching) return;
  const files = [...(e.dataTransfer?.files ?? [])];
  if (files.length === 0) return;

  // Resolve channelId synchronously — activeElement is unreliable after any await.
  const channelId = getInterceptorChannelId();

  // Stop unconditionally BEFORE the _attachmentPending check. Returning early
  // without stopping lets the trusted drop fall through to Discord raw.
  e.stopImmediatePropagation();
  e.preventDefault();

  if (_attachmentPending) return;

  try {
    const dt = await encryptFileList(files, channelId);

    const onChange = getFileInputOnChange();

    onChange({ currentTarget: { files: dt.files, err: null } });
    _attachmentPending = true;
    watchTrayAndClearPending();

  } catch (dropErr) {
    err('drop: failed — %s', dropErr?.message ?? dropErr);
  }
}, true);

// ─── change (file picker) ─────────────────────────────────────────────────────
// input.files is overridden via Object.defineProperty — the only way to replace
// a FileList on an existing <input>. The override is deleted immediately after
// dispatch: Discord reads input.files synchronously inside its React handler, so
// the delete happens after consumption. Without it, the encrypted FileList from
// the previous upload permanently shadows the native 'files' property.
document.addEventListener('change', async (e) => {
  if (_locked || !_activeEntry || _redispatching) return;
  const input = e.target;
  if (input?.type !== 'file') return;

  // Delete any leftover override before reading so we get the real selection.
  try { delete input.files; } catch { /* non-configurable — already native */ }
  const files = [...(input.files ?? [])];
  if (files.length === 0) return;

  const channelId = getInterceptorChannelId();

  // Stop unconditionally — same reason as drop.
  e.stopImmediatePropagation();
  e.preventDefault();

  if (_attachmentPending) {
    // File-picker is an explicit user action. A stale pending flag means the
    // prior drop's tray silently never appeared. Reset rather than discarding.
    _attachmentPending = false;
    window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, '*');
  }

  const dt = await encryptFileList(files, channelId);

  try {
    Object.defineProperty(input, 'files', {
      value:        dt.files,
      configurable: true,
      writable:     false,
      enumerable:   true,
    });
  } catch (ex) {
    err('defineProperty input.files failed:', ex?.message);
  }

  _redispatching = true;
  try {
    input.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
  } finally {
    _redispatching = false;
    try {
      delete input.files;
    } catch {
      err('change: could not delete input.files override — sticky bug may recur');
    }
  }
}, true);

// ─── paste ────────────────────────────────────────────────────────────────────
document.addEventListener('paste', async (e) => {
  if (_locked || !_activeEntry || _redispatching) return;
  const files = [...(e.clipboardData?.files ?? [])];
  if (files.length === 0) return;

  const channelId = getInterceptorChannelId();

  e.stopImmediatePropagation();
  e.preventDefault();

  if (_attachmentPending) {
    // Paste is an explicit user action — same rationale as the change handler:
    // reset rather than silently discard, in case the prior upload's tray never appeared.
    _attachmentPending = false;
    window.postMessage({ type: 'AGE_ATTACHMENT_CLEARED' }, '*');
  }

  const dt = await encryptFileList(files, channelId);

  _redispatching = true;
  try {
    e.target.dispatchEvent(new ClipboardEvent('paste', {
      bubbles:       true,
      cancelable:    true,
      clipboardData: dt,
    }));
  } finally {
    _redispatching = false;
  }
}, true);
