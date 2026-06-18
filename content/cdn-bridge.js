// cdn-bridge.js — Discord Age Encryption
//
// Runs inside a hidden <iframe> injected into the Discord page by content.js.
// Fetches from cdn.discordapp.com (permitted by host_permissions on the extension
// origin) and transfers the raw ArrayBuffer back via postMessage transferables.
// All crypto (sig verify + age decrypt) is handled by content.js / file-crypto-worker.js.

'use strict';

window.addEventListener('message', async (e) => {
  if (e.source !== window.parent) return;
  const { type, requestId, cdnUrl, parentOrigin } = e.data ?? {};
  if (type !== 'AGE_FETCH_RAW') return;

  function reply(payload) {
    window.parent.postMessage(payload, parentOrigin, payload.buffer ? [payload.buffer] : []);
  }

  try {
    if (!cdnUrl || typeof cdnUrl !== 'string')
      throw new Error('AGE_FETCH_RAW: cdnUrl missing');
    if (!parentOrigin)
      throw new Error('AGE_FETCH_RAW: parentOrigin missing');

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

// Signal readiness to the parent.
window.parent.postMessage({ type: 'AGE_IFRAME_READY' }, '*');
