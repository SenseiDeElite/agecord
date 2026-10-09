/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// cdn-bridge.js — Agecord

// Hidden iframe bridge for extension-origin cross-origin fetches.
// Transfers fetched ArrayBuffers to the parent via postMessage.
// Crypto is handled by content.js and file-crypto-worker.js.

'use strict';

// Trusted parent origin from this iframe's src query.
// Used exclusively for postMessage origin validation and replies.
// Do not trust origin values supplied in message payloads.
const expectedParentOrigin = new URLSearchParams(location.search).get('parentOrigin');

// Only Discord attachment URLs are fetched; mirrors CDN_ATTACHMENT_PATH_PATTERN
function isAllowedCdnUrl(raw) {
  const u = URL.parse(raw);
  return !!u
    && u.protocol === 'https:'
    && u.hostname === 'cdn.discordapp.com'
    && !u.port
    && !u.username && !u.password
    && /^\/attachments\/\d+\//.test(u.pathname);
}

window.addEventListener('message', async (e) => {
  if (e.source !== window.parent) return;
  if (!expectedParentOrigin || e.origin !== expectedParentOrigin) return;

  const { type, requestId, cdnUrl } = e.data ?? {};
  if (type !== 'AGE_FETCH_RAW') return;

  function reply(payload) {
    window.parent.postMessage(payload, expectedParentOrigin, payload.buffer ? [payload.buffer] : []);
  }

  try {
    if (!cdnUrl || typeof cdnUrl !== 'string')
      throw new Error('AGE_FETCH_RAW: cdnUrl missing');
    if (!isAllowedCdnUrl(cdnUrl))
      throw new Error('AGE_FETCH_RAW: cdnUrl not allowed');

    // cache: 'no-store' — ArrayBuffer is transferred (neutered) to content.js;
    // a cached response returns an ArrayBuffer(0) on the second fetch, silently
    // failing the SIG_BYTES length check.
    const resp = await fetch(cdnUrl, { cache: 'no-store' });
    if (!resp.ok) throw new Error(`CDN fetch failed: ${resp.status} ${resp.statusText}`);
    const rawBuffer = await resp.arrayBuffer();

    reply({ type: 'AGE_FETCH_RAW_RESULT', requestId, buffer: rawBuffer });

  } catch (err) {
    console.error('[age-iframe] AGE_FETCH_RAW error requestId=%s:', requestId, err?.message ?? err);
    reply({ type: 'AGE_FETCH_RAW_RESULT', requestId, error: err?.message ?? String(err) });
  }
});

// Signal readiness to the parent using its origin from the src query.
// Avoids '*' and ancestorOrigins, which may be redacted by Referrer-Policy.
if (expectedParentOrigin) {
  window.parent.postMessage({ type: 'AGE_IFRAME_READY' }, expectedParentOrigin);
} else {
  console.error('[age-iframe] AGE_IFRAME_READY: parentOrigin missing from iframe src');
}
