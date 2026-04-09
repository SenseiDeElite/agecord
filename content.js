// content.js — Discord Age Encryption
//
// Wire format : [age]:<base64disc_payload>:<base64disc_ed25519_sig>
// Crypto      : age-encryption (X25519 + ChaCha20-Poly1305) + Ed25519 signatures
// Compression : deflate-raw applied to plaintext before encryption
// Sig input   : UTF-8("<channelId>:<cipher>") — channel ID binds sig to channel,
//               preventing cross-channel replay without using wire-format space.
// Encoding    : both cipher and sig use the "disc" base64 alphabet (+ → -  / → .)
//               so that neither field ever contains _ which Discord renders as
//               underline markup and strips from the DOM.
//
// Depends on  : lib/age.min.js, content/emoji_map.js (loaded first via manifest)
//
// Decryption is delegated to the background service worker so the raw age
// identity never enters the content script's memory.

(() => {
  'use strict';

  const PREFIX = '[age]';

  // _decryptedCache: Map<msgId (li.id), plaintext>
  // Keyed on stable li.id so React DOM reconciliation can re-render instantly.
  const _processedIds   = new Set();
  const _decryptedCache = new Map();

  // _outgoingCache: Map<cipherBase64disc, plaintext>
  // Populated when we send a message; lets us render our own message immediately
  // without a background decrypt round-trip. TTL: 8 s.
  const _outgoingCache = new Map();

  let _signingKey  = null;   // non-extractable CryptoKey (Ed25519 private), from background
  let _contacts    = {};
  let _globalOn    = true;
  let _msgObserver = null;

  const sleep    = ms => new Promise(r => setTimeout(r, ms));
  const localGet = keys => new Promise(r => chrome.storage.local.get(keys, r));

  // ─── DOM helpers ─────────────────────────────────────────────────────────────

  function getTextbox()     { return document.querySelector('[data-slate-editor="true"]'); }
  function getMessageList() { return document.querySelector('ol[data-list-id="chat-messages"]'); }

  function getCurrentChannelId() {
    const m = location.pathname.match(/\/channels\/[^/]+\/(\d+)/);
    return m ? m[1] : null;
  }

  function getContact() {
    const id = getCurrentChannelId();
    return id ? (_contacts[id] ?? null) : null;
  }

  // ─── Enter key interception ───────────────────────────────────────────────────

  function isEncryptionActive() {
    return !!(_signingKey && getContact()?.enabled && _globalOn);
  }

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

  // ─── Crypto helpers (content-side) ────────────────────────────────────────────
  // Only public-key operations live here; decryption is handled by the background.

  async function importVerifyKey(contactKeyString) {
    const m = contactKeyString.match(/;ed25519:([A-Za-z0-9_-]+)$/);
    if (!m) return null;
    const raw = base64UrlToBytes(m[1]);
    return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  }

  // ─── Encryption (outgoing) ────────────────────────────────────────────────────

  async function encryptMessage(plaintext, contact) {
    const enc = new age.Encrypter();
    enc.addRecipient(contact.ageRecipient.split(';')[0]);
    const self = await localGet(['ageRecipient']);
    if (self.ageRecipient) enc.addRecipient(self.ageRecipient.split(';')[0]);
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
    const contact   = getContact();
    const channelId = getCurrentChannelId();
    const plain     = getTextbox()?.innerText?.trim();
    if (!plain || !contact || !channelId) return;
    _sending = true;
    try {
      const cipher = await encryptMessage(plain, contact);

      // Signature input binds to channel ID (replay prevention) + ciphertext.
      const sigInput = new TextEncoder().encode(`${channelId}:${cipher}`);
      const sigBytes = await crypto.subtle.sign('Ed25519', _signingKey, sigInput);
      // Clamp to 64 bytes — some Chromium builds return 65 bytes from Ed25519 sign.
      const sig = bytesToBase64Disc(new Uint8Array(sigBytes).slice(0, 64));

      // Cache own outgoing message by cipher so we can render it immediately
      // when it echoes back in the message list, without a background decrypt.
      _outgoingCache.set(cipher, plain);
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
      if (cached && el.dataset.ageState !== 'ok') renderDecrypted(el, cached);
      return;
    }

    const text = el.dataset.ageRaw ?? directTextContent(el).trim();
    if (!text.startsWith(PREFIX)) return;

    // New wire format: [age]:<cipher>:<sig>
    const m = text.match(/^\[age\]:([A-Za-z0-9\-.]+):([A-Za-z0-9\-.]+)$/);
    if (!m) return;

    el.dataset.ageRaw = text;

    if (!_signingKey || !_globalOn) {
      markMessage(el, !_signingKey ? '🔒 Unlock extension to decrypt.' : '🔒 Decryption disabled.', 'pending');
      return;
    }

    // Own outgoing message: render from cache without background round-trip.
    const cipher = m[1];
    const outgoingPlain = _outgoingCache.get(cipher);
    if (outgoingPlain !== undefined) {
      _processedIds.add(msgId);
      _decryptedCache.set(msgId, outgoingPlain);
      renderDecrypted(el, outgoingPlain);
      return;
    }

    markMessage(el, '🔒 Decrypting…', 'pending');

    (async () => {
      const channelId   = getCurrentChannelId();
      const sig         = m[2];
      const sigInput    = new TextEncoder().encode(`${channelId}:${cipher}`);
      const sigBytes    = base64DiscToBytes(sig).slice(0, 64); // clamp for Chromium

      const contact    = getContact();
      const contactKey = contact ? await importVerifyKey(contact.ageRecipient).catch(() => null) : null;

      if (!contactKey) {
        // No contact configured for this channel — cannot verify sender.
        console.info('[age] no contact key for channel', channelId, '— msgId', msgId);
        markMessage(el, '⚠️ No contact configured for this channel.', 'warn');
        return;
      }

      const sigValid = await crypto.subtle.verify('Ed25519', contactKey, sigBytes, sigInput);
      if (!sigValid) {
        console.info('[age] signature mismatch — msgId', msgId);
        markMessage(el, '🔴 Signature invalid — possible tampering.', 'error');
        return;
      }

      // Signature is valid — delegate decryption to the background.
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'DECRYPT_MSG', cipher });
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
        // Background sends signingKeyB64 — the PKCS8 private key as base64url.
        // CryptoKey objects cannot survive chrome.tabs.sendMessage (JSON IPC
        // silently drops them), so we import the raw bytes locally instead.
        try {
          const data  = await localGet(['contacts', 'globalOn']);
          _contacts   = data.contacts || {};
          _globalOn   = data.globalOn !== false;
          const pkcs8 = base64UrlToBytes(msg.signingKeyB64);
          _signingKey = await crypto.subtle.importKey(
            'pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']
          );
          attachEnterHook();
          scanExisting();
          rescanPending();
        } catch (e) {
          console.error('[age] unlock error:', e);
        }
        return;
      }

      if (msg.type === 'CONTACTS_UPDATED') {
        const prevOn = _globalOn;
        const data   = await localGet(['contacts', 'globalOn']);
        _contacts = data.contacts || {};
        _globalOn = data.globalOn !== false;
        if (_globalOn && !prevOn) {
          _processedIds.clear();
          _decryptedCache.clear();
          rescanPending();
        } else if (!_globalOn && prevOn) {
          _processedIds.clear();
          _decryptedCache.clear();
          document.querySelectorAll('[id^="message-content-"][data-age-state="ok"]').forEach(el => {
            el.dataset.ageState = '';
            markMessage(el, '🔒 Decryption disabled.', 'pending');
          });
        }
        return;
      }

      if (msg.type === 'RELOCK') {
        _signingKey = null;
        _processedIds.clear();
        _decryptedCache.clear();
        _outgoingCache.clear();
        detachEnterHook();
        document.querySelectorAll('[id^="message-content-"][data-age-state="ok"]').forEach(el => {
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
      setTimeout(() => {
        if (_signingKey) attachEnterHook();
        _msgObserver?.disconnect();
        waitForMessageList();
      }, 800);
    }).observe(document.body, { subtree: true, childList: true });
  }

  // ─── Init ────────────────────────────────────────────────────────────────────

  async function init() {
    listenForMessages();
    startNavObserver();
    const data = await localGet(['contacts', 'globalOn']);
    _contacts = data.contacts || {};
    _globalOn = data.globalOn !== false;
    waitForMessageList();
  }

  if (document.body) {
    init().catch(e => console.error('[age] init error:', e));
  } else {
    document.addEventListener('DOMContentLoaded', () => init().catch(e => console.error('[age] init error:', e)));
  }

})();
