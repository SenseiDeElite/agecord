/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// upload-interceptor.js — Agecord

// Everything below runs inside one function scope: this file executes in the page's MAIN world,
// so top-level let/const/function would otherwise become globals shared with Discord's own scripts.
(() => {
  'use strict';

  function err(...a)  { console.error('[agecord-intercept]', ...a); }
  function info(...a) { console.info('[agecord-intercept]', ...a); }

  // ─── Lock state (cosmetic only) ────────────────────────────────────────────────

  // Best-effort snapshot for dragover cursor hints; upload gating is always live.
  let _locked = true;
  let _activeEntry = false;
  Object.defineProperty(window, '__agecordLocked', { get: () => _locked, configurable: true });

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

  // ─── Draft panes (forum post / new thread) ─────────────────────────────────────

  // Drafts have no channel ID until posted; leave them unchanged.
  // New thread: a role-less <section> contains the NO_LIST___ preview, composer,
  // popups, and drop overlay (overlay is outside the form).
  // Forum post: composer/form are inside the forum list; drop overlay is its sibling.
  // Never classify content under section[role="complementary"] as a draft.
  // KEEP IN SYNC with content/content.js.

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

  // ─── Foreign UI ─────────────────────────────────────────────

  // Uploads using Discord's plumbing outside the message composer must reach their own handler unchanged.
  // Exclude by category, not component, so new Discord surfaces need no new entries:
  // third-party UI (e.g. Vencord Themes) and modals/dialogs without a message composer.
  const FOREIGN_UI_SEL = '.vc-settings-tab';
  const MODAL_UI_SEL   = '[role="dialog"], [aria-modal="true"]';
  const SLATE_SEL      = '[data-slate-editor="true"]';
  const MESSAGE_ITEM_SEL = 'li[id^="chat-messages-"]';

  // A message composer form: holds a Slate editor and is not an edit box
  // inside a message row (Discord's search bar is a Slate editor with no form).
  function isComposerForm(form) {
    return !!form && !form.closest(MESSAGE_ITEM_SEL) && !!form.querySelector(SLATE_SEL);
  }

  function containsComposer(root) {
    return [...root.querySelectorAll(SLATE_SEL)].some(ed => isComposerForm(ed.closest('form')));
  }

  function isForeignUiTarget(el) {
    if (!el?.closest) return false;
    if (el.closest(FOREIGN_UI_SEL)) return true;
    const dialog = el.closest(MODAL_UI_SEL);
    return !!dialog && !containsComposer(dialog);
  }

  // ─── Source pane ──────────────────────────────────────────────────────────────

  // Deliver to the pane the event came from, never to whichever composer happens
  // to hold focus: after a file-picker click, a drop or a paste outside the
  // textbox, focus says nothing about the user's intent (split view).
  const PANE_SEL = 'main, section[role="complementary"]';

  // Chat pane an element belongs to. Discord's drop overlay is a sibling of
  // <main>, so use the nearest ancestor that contains exactly one pane.
  // null when ambiguous (e.g. sidebar) — callers then fall back to focus.
  function ownerPane(el) {
    for (let n = el; n && n.nodeType === 1 && n !== document.body; n = n.parentElement) {
      if (n.matches(PANE_SEL)) return n;
      const panes = n.querySelectorAll(PANE_SEL);
      if (panes.length === 1) return panes[0];
      if (panes.length > 1) return null;
    }
    return null;
  }

  // { pane, form } the event targets. Both are null when the source is unknown
  // (ambiguous target, or a pane with no composer such as a locked thread):
  // the focus-based lookup then decides, for the id and the destination alike.
  function resolveUploadSource(el) {
    const own  = el?.closest?.('form');
    const pane = ownerPane(el);
    const form = isComposerForm(own)
      ? own
      : (pane ? [...pane.querySelectorAll('form')].find(isComposerForm) ?? null : null);
    return form ? { pane, form } : { pane: null, form: null };
  }

  // Text-only pastes become attachments only when pasted into a real composer.
  function isComposerTarget(el) {
    return isComposerForm(el?.closest?.('form'));
  }

  // ─── Attachment-pending guard ─────────────────────────────────────────────────

  // Blocks all attachment entry-points until the upload tray clears.
  let _attachmentPending = false;

  // ─── postMessage round-trip ───────────────────────────────────────────────────

  const _pending = new Map();

  // Unguessable request ids.
  // content.js has its own copy of this helper: the two worlds cannot share code.
  function newRequestId() {
    return crypto.getRandomValues(new Uint8Array(16)).toHex();
  }

  window.addEventListener('message', (e) => {
    if (e.source !== window) return;
    const { type, requestId } = e.data ?? {};

    if (type === 'AGECORD_ENCRYPT_FILE_ACK' && _pending.has(requestId)) {
      const entry = _pending.get(requestId);
      entry.onAck?.();
    }

    if (type === 'AGECORD_ENCRYPT_FILE_RESULT' && _pending.has(requestId)) {
      const { resolve, reject, fileName } = _pending.get(requestId);
      _pending.delete(requestId);
      if (e.data.error) {
        (e.data.errorCode === 'PASSTHROUGH' ? info : err)('encrypt FAILED requestId=%s fileName=%s —', requestId, fileName, e.data.error);
        reject(Object.assign(new Error(e.data.error), { code: e.data.errorCode }));
      } else {
        resolve({ buffer: e.data.buffer, encryptedName: e.data.encryptedName });
      }
    }

    // ── AGECORD_ENCRYPT_TEXT_MESSAGE ─────────────────────────────────────────────────

    // Same round-trip shape as AGECORD_ENCRYPT_FILE, but content.js runs the message
    // (compress+sign) pipeline instead of the generic file pipeline — used so a
    // long paste can be sent as message.txt.age, identical to a typed send.
    if (type === 'AGECORD_ENCRYPT_TEXT_MESSAGE_ACK' && _pending.has(requestId)) {
      const entry = _pending.get(requestId);
      entry.onAck?.();
    }

    if (type === 'AGECORD_ENCRYPT_TEXT_MESSAGE_RESULT' && _pending.has(requestId)) {
      const { resolve, reject } = _pending.get(requestId);
      _pending.delete(requestId);
      if (e.data.error) {
        (e.data.errorCode === 'PASSTHROUGH' ? info : err)('encrypt text message FAILED requestId=%s —', requestId, e.data.error);
        reject(Object.assign(new Error(e.data.error), { code: e.data.errorCode }));
      } else {
        resolve(e.data.buffer);
      }
    }

    if (type === 'AGECORD_INTERCEPTOR_STATE') {
      _locked = !e.data.unlocked;
      _activeEntry = !!e.data.activeEntry;
    }

    // Triggers upload preview via React onChange.
    // Avoids DOM events and async bypass handling issues.
    if (type === 'AGECORD_DO_UPLOAD') {
      try {
        uploadSignedMessageBytes(e.data.buffer);
        window.postMessage({ type: 'AGECORD_DO_UPLOAD_RESULT', requestId, ok: true }, '*');
      } catch (uploadErr) {
        err('AGECORD_DO_UPLOAD failed:', uploadErr.message);
        window.postMessage({ type: 'AGECORD_DO_UPLOAD_RESULT', requestId, ok: false, error: uploadErr.message }, '*');
      }
    }

    // ── AGECORD_UPLOAD_TEXT_AS_FILE ──────────────────────────────────────────────────

    // Long messages need encrypted-file delivery; this explicit action must never
    // fall back to plaintext.
    if (type === 'AGECORD_UPLOAD_TEXT_AS_FILE') {
      const { text, channelId: uploadChannelId, guildId: uploadGuildId } = e.data;
      (async () => {
        // Set the gate before awaiting encryption to prevent concurrent flows.
        _attachmentPending = true;
        try {
          const file = new File([text], 'message.txt', { type: 'text/plain' });
          await deliverEncryptedFiles([file], uploadChannelId, uploadGuildId);
          window.postMessage({ type: 'AGECORD_UPLOAD_TEXT_AS_FILE_RESULT', requestId, ok: true }, '*');
        } catch (uploadErr) {
          _attachmentPending = false; // nothing delivered — don't leave the gate stuck shut
          err('AGECORD_UPLOAD_TEXT_AS_FILE failed:', uploadErr.message);
          window.postMessage({ type: 'AGECORD_UPLOAD_TEXT_AS_FILE_RESULT', requestId, ok: false, error: uploadErr.message }, '*');
        }
      })();
    }

    if (type === 'AGECORD_ATTACHMENT_CLEARED') {
      _attachmentPending = false;
    }

    // 800 ms delay prevents a reload loop on extension uninstall.
    if (type === 'AGECORD_CONTEXT_INVALIDATED') {
      setTimeout(() => location.reload(), 800);
    }

    // Sticker click: replace composer content with the sticker URL (see content.js, sticker interception).
    if (type === 'AGECORD_REPLACE_COMPOSER_TEXT') {
      const { text, token } = e.data;
      if (typeof text === 'string' && text.length > 0 && text.length <= 2048 &&
          typeof token === 'string' && /^[0-9a-f]{32}$/.test(token)) {
        // Exactly the composer content.js evaluated (draft/channel gate); never fall back to another one.
        const tb = document.querySelector(`[data-slate-editor="true"][data-agecord-sticker-target="${token}"]`);
        if (tb) {
          tb.removeAttribute('data-agecord-sticker-target');
          if (tb.closest('form') && !tb.closest('li[id^="chat-messages-"]')) clearSlateTextbox(text, tb);
        }
      }
    }

    if (type === 'AGECORD_CLEAR_TEXTBOX') {
      const nonce = e.data?.nonce;
      const ok = clearSlateTextbox();
      window.postMessage(
        ok ? { type: 'AGECORD_CLEAR_TEXTBOX_RESULT', ok: true,  nonce }
           : { type: 'AGECORD_CLEAR_TEXTBOX_RESULT', ok: false, nonce, error: 'clearSlateTextbox failed' },
        '*'
      );
    }

    // ── AGECORD_GET_SLATE_TEXT ──────────────────────────────────────────────────────

    // Must run in page context: the isolated world gets a proxy of the React
    // fiber heap, not the live instance.
    // Custom emoji <img> nodes are serialised as [name](url) markdown.
    if (type === 'AGECORD_GET_SLATE_TEXT') {
      const nonce = e.data?.nonce;
      const tb = getMainTextbox();
      if (!tb) {
        // Answer immediately so the content script doesn't wait out its timeout.
        console.warn('[agecord] Slate textbox not found');
        window.postMessage({ type: 'AGECORD_GET_SLATE_TEXT_RESULT', ok: false, nonce }, '*');
        return;
      }

      // Any exception while serialising the composer must still produce a reply: otherwise the content script
      // waits out its timeout and silently aborts a send whose Enter was already consumed.
      try {
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
        // (?<!\n) starts only at the beginning of a newline run; bare /\n+$/ rescanned every run from each newline in it.
        const serialised = lineText.replace(/(?<!\n)\n+$/, '');
        lines.push(isBlockquote ? '> ' + serialised : serialised);
      }

      const text = lines.join('\n').trim() ||
                   (tb.innerText?.trim() ?? '');

      window.postMessage({ type: 'AGECORD_GET_SLATE_TEXT_RESULT', ok: true, text, nonce }, '*');
      } catch (readErr) {
        err('AGECORD_GET_SLATE_TEXT failed:', readErr?.message ?? readErr);
        window.postMessage({ type: 'AGECORD_GET_SLATE_TEXT_RESULT', ok: false, nonce }, '*');
      }
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
        // Match the whole composer form: the attach/emoji buttons are not inside the textbox.
        const ancestor = composers.find(c => c.closest('form')?.contains(active));
        if (ancestor) return ancestor;
      }
    }

    // Composers only: never the search bar or an inline edit box. null when the
    // channel has no composer, so callers fail visibly instead of using a wrong editor.
    return composers[0] ?? null;
  }

  // Resolves the active composer route at capture time; returns IDs together to avoid post-await route races.
  // The channel is read from the pane's message rows (chat-messages-<channelId>-<messageId>);
  // the intro row keeps empty channels resolvable. Usually this matches the URL, but it matters
  // when the pane shows a different channel (e.g. a stale thread after navigation).
  // null when not rendered. 
  // KEEP IN SYNC with content.js
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

  // sourcePane: the pane the event came from (see ownerPane). When null, use the
  // pane of the composer getFileInputOnChange() will deliver to, so the id
  // always matches the destination (walking up from document.activeElement is
  // wrong: Discord's search bar sits inside a <section> that is not a pane).
  function getInterceptorLocation(sourcePane = null) {
    // Determine whether the receiving composer is inside MAIN or SECTION so we
    // can pick the right ID in split thread view.
    const pane = sourcePane ?? getMainTextbox()?.closest(PANE_SEL) ?? null;
    const composerRole = pane ? (pane.tagName === 'MAIN' ? 'MAIN' : 'SECTION') : null;

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
      // With no thread in the URL, a side pane is the URL's voice chat (same id).
      // If it ever shows another channel, its own message ids say which.
      const sidePaneChannel = composerRole === 'SECTION' ? paneChannelId(pane) : null;
      return { channelId: sidePaneChannel ?? channelId, guildId };
    }

    return { channelId: null, guildId: null };
  }

  // replacement === undefined: clear. A string: replace the whole composer content with it.
  // tbOverride: the exact composer to edit (sticker replace); otherwise the main/focused one.
  function clearSlateTextbox(replacement, tbOverride) {
    try {
      const tb = tbOverride ?? getMainTextbox();
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

      if (typeof replacement === 'string') {
        // Selection is collapsed at the start after deleteFragment; insertText goes through
        // Slate's normal pipeline, so Discord's onChange/draft handling sees an ordinary edit.
        editor.insertText(replacement);
        // Closing the picker can hand focus back to its trigger button; Enter must reach the composer.
        tb.focus();
        setTimeout(() => tb.focus(), 100);
        return true;
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
  const ACK_TIMEOUT_MS    = 2_000;
  const ENCRYPT_TIMEOUT_MS = 20_000;

  // Tracks postMessage requests with ACK/result phases.
  // Stores extra fields for response handling.
  function withPendingRequest(buildPayload, extraEntryFields = {}) {
    const { fileName } = extraEntryFields;
    const label = fileName ? ` fileName=${fileName}` : '';

    return new Promise((resolve, reject) => {
      const requestId = newRequestId();
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

  function encryptFile(fileName, mimeType, buffer, channelId, guildId) {
    return withPendingRequest(
      (requestId) => {
        window.postMessage(
          { type: 'AGECORD_ENCRYPT_FILE', requestId, fileName, mimeType, buffer, channelId, guildId },
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
      const { buffer: encBuffer, encryptedName } = await encryptFile(file.name, file.type, plainBuffer, channelId, guildId);
      dt.items.add(new File([encBuffer], encryptedName, { type: 'application/octet-stream' }));
    }
    return dt;
  }

  // Delivers files to React and starts tray tracking.
  // _attachmentPending is set by the caller before encryption.
  // sourceForm: composer form of the pane the upload came from; omitted by
  // typed-send callers, which keep the focus-based lookup.
  function deliverFileList(dt, sourceForm) {
    const onChange = getFileInputOnChange(sourceForm);
    onChange({ currentTarget: { files: dt.files, err: null } });
    watchTrayAndClearPending();
  }

  // Encrypts files and delivers them in one step — the common case for every
  // upload entry point below.
  async function deliverEncryptedFiles(files, channelId, guildId, sourceForm) {
    deliverFileList(await encryptFileList(files, channelId, guildId), sourceForm);
  }

  // Only explicit PASSTHROUGH permits raw delivery; all other failures rethrow.
  // Set _attachmentPending before await to serialize concurrent upload flows.
  async function deliverFilesRespectingGate(files, channelId, guildId, sourceForm) {
    _attachmentPending = true;
    try {
      await deliverEncryptedFiles(files, channelId, guildId, sourceForm);
    } catch (e) {
      if (e?.code === 'PASSTHROUGH') {
        const dt = new DataTransfer();
        for (const f of files) dt.items.add(f);
        try {
          deliverFileList(dt, sourceForm);
        } catch (deliverErr) {
          _attachmentPending = false; // delivery threw before tray tracking started
          throw deliverErr;
        }
        return;
      }
      _attachmentPending = false; // nothing delivered — don't leave the gate stuck shut
      throw e; // BLOCKED, timeout, worker error — nothing delivered.
    }
  }

  // Clears a stale _attachmentPending flag left behind by a drop whose tray
  // never appeared. Not used by the drop handler itself.
  function clearStalePending() {
    if (!_attachmentPending) return;
    _attachmentPending = false;
    window.postMessage({ type: 'AGECORD_ATTACHMENT_CLEARED' }, '*');
  }

  // Signs text through content.js pipeline.
  // Returns signed Agecord bytes; no plaintext fallback.
  function encryptTextMessage(text, channelId, guildId) {
    return withPendingRequest((requestId) => {
      window.postMessage({ type: 'AGECORD_ENCRYPT_TEXT_MESSAGE', requestId, text, channelId, guildId }, '*');
    });
  }

  // Wraps already-signed Agecord bytes as message.txt.age and hands them to React's
  // onChange, identical to what AGECORD_DO_UPLOAD and the paste handler both need —
  // factored out so neither has to duplicate the DataTransfer/File plumbing.
  function uploadSignedMessageBytes(buffer, sourceForm) {
    const file = new File([buffer], 'message.txt.age', { type: 'application/octet-stream' });
    const dt   = new DataTransfer();
    dt.items.add(file);
    deliverFileList(dt, sourceForm);
  }

  // PASSTHROUGH path for long pasted text: deliver raw message.txt.
  function deliverPlainTextFile(text, sourceForm) {
    const file = new File([text], 'message.txt', { type: 'text/plain' });
    const dt   = new DataTransfer();
    dt.items.add(file);
    deliverFileList(dt, sourceForm);
  }

  // ─── Shared helpers ───────────────────────────────────────────────────────────

  // Returns React's onChange from the file input of the source composer form when
  // given, else the one closest to the active composer.
  // Throws if the input or its React props are missing.
  function getFileInputOnChange(sourceForm) {
    const activeForm = sourceForm?.isConnected
      ? sourceForm
      : getMainTextbox()?.closest('form');
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
    let trayGoneObserver = null;
    function clearOnce() {
      if (fired) return;
      fired = true;
      trayAppearObserver.disconnect();
      trayGoneObserver?.disconnect();
      _attachmentPending = false;
      window.postMessage({ type: 'AGECORD_ATTACHMENT_CLEARED' }, '*');
    }

    function watchForTrayGone() {
      trayGoneObserver = new MutationObserver(() => {
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
    if (isDraftTarget(e.target) || isForeignUiTarget(e.target)) return; // native handling
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  }, true);

  // ─── drop (window) ────────────────────────────────────────────────────────────

  // Window capture required; Discord blocks document capture.
  // Uses React onChange because synthetic drag events are rejected.
  window.addEventListener('drop', async (e) => {
    const files = [...(e.dataTransfer?.files ?? [])];
    if (files.length === 0) return;

    // Draft panes / foreign UI: classify BEFORE stopping the event so it is handled natively.
    if (isDraftTarget(e.target) || isForeignUiTarget(e.target)) return;

    // Resolve channelId/guildId synchronously — activeElement (and location.href's
    // relevance to it) is unreliable after any await.
    const src = resolveUploadSource(e.target);
    const { channelId, guildId } = getInterceptorLocation(src.pane);

    // Stop unconditionally BEFORE the _attachmentPending check. Returning early
    // without stopping lets the trusted drop fall through to Discord raw.
    e.stopImmediatePropagation();
    e.preventDefault();

    if (_attachmentPending) return;

    try {
      await deliverFilesRespectingGate(files, channelId, guildId, src.form);
    } catch (dropErr) {
      err('drop: failed — %s', dropErr?.message ?? dropErr);
    }
  }, true);

  // ─── change (file picker) ─────────────────────────────────────────────────────

  // Call React onChange directly. Dispatching a synthetic 'change'
  // would re-enter this capture listener, clear the files override, and swallow
  // the upload before Discord's handler. Direct invocation avoids recursion.
  document.addEventListener('change', async (e) => {
    const input = e.target;
    if (input?.type !== 'file') return;
    if (isDraftTarget(input) || isForeignUiTarget(input)) return; // native handling, before touching input.files

    // Delete any leftover override before reading so we get the real selection.
    try { delete input.files; } catch { /* non-configurable — already native */ }
    const files = [...(input.files ?? [])];
    if (files.length === 0) return;

    const src = resolveUploadSource(input);
    const { channelId, guildId } = getInterceptorLocation(src.pane);

    // Stop unconditionally — same reason as drop.
    e.stopImmediatePropagation();
    e.preventDefault();

    // File-picker is an explicit user action. A stale pending flag means the
    // prior drop's tray silently never appeared. Reset rather than discarding.
    clearStalePending();

    try {
      await deliverFilesRespectingGate(files, channelId, guildId, src.form);
    } catch (changeErr) {
      err('change: failed — %s', changeErr?.message ?? changeErr);
    }
  }, true);

  // ─── paste ────────────────────────────────────────────────────────────────────

  // Firefox lacks clipboardData on synthetic events; call onChange directly.
  // Intercepts pasted text before Discord creates message.txt.
  // Limits match Discord message handling thresholds.
  const NATIVE_PASTE_FILE_THRESHOLD = 2000;
  // KEEP IN SYNC (content/content.js MAX_INLINE_MESSAGE_CHARS)
  const MESSAGE_TEXT_MAX_CHARS      = 4000;

  document.addEventListener('paste', async (e) => {
    const files = [...(e.clipboardData?.files ?? [])];
    const text  = files.length === 0 ? (e.clipboardData?.getData('text/plain') ?? '') : '';

    const needsInterception = files.length > 0 || text.length > NATIVE_PASTE_FILE_THRESHOLD;
    if (!needsInterception) return;
    if (isDraftTarget(e.target) || isForeignUiTarget(e.target)) return; // native handling
    // Long text pasted anywhere but a message composer (search bar, edit box,
    // any other field) is just text.
    if (files.length === 0 && !isComposerTarget(e.target)) return;

    const src = resolveUploadSource(e.target);
    const { channelId, guildId } = getInterceptorLocation(src.pane);

    e.stopImmediatePropagation();
    e.preventDefault();

    clearStalePending();

    try {
      if (files.length > 0) {
        await deliverFilesRespectingGate(files, channelId, guildId, src.form);
      } else if (text.length <= MESSAGE_TEXT_MAX_CHARS) {
        // Single-message path: use the typed-send compress+sign pipeline.
        // Keep PASSTHROUGH handling here; generic file delivery is separate.
        try {
          const buffer = await encryptTextMessage(text, channelId, guildId);
          uploadSignedMessageBytes(buffer, src.form);
        } catch (msgErr) {
          if (msgErr?.code === 'PASSTHROUGH') {
            deliverPlainTextFile(text, src.form);
          } else {
            throw msgErr; // BLOCKED, timeout, worker error — nothing delivered.
          }
        }
      } else {
        // Too long for a single encrypted message — attach the full,
        // untruncated text as a real encrypted file instead.
        const textFile = new File([text], 'message.txt', { type: 'text/plain' });
        await deliverFilesRespectingGate([textFile], channelId, guildId, src.form);
      }
    } catch (pasteErr) {
      err('paste: failed — %s', pasteErr?.message ?? pasteErr);
    }
  }, true);
})();
