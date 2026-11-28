/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// cdn-bridge.js — Agecord

// Hidden iframe bridge for extension-origin cross-origin fetches.
// Transfers fetched ArrayBuffers to the parent over a private MessageChannel port.

// Crypto is handled by content.js and file-crypto-worker.js.

'use strict';

// One-time secret from this iframe's URL hash, known only to content.js (the iframe sits in a closed
// shadow root, so the page cannot read src). A bridge framed by the page has no secret and is never
// initialised. After INIT, all traffic uses the private MessageChannel port; window messages are ignored.
const secret = location.hash.slice(1);
let port = null;

// Both limits mirror content.js (the two worlds cannot share code).
const SIG_VERSION = 0x01;                  // KEEP IN SYNC (content.js SIG_VERSION)
const HEADER_LEN  = 1 + 4627 + 3457;       // KEEP IN SYNC (content.js: version + SIG_BYTES + PUBKEY_HINT_LEN) = 8,085
const HARD_MAX    = 2 ** 30;

const isInt = (v, max) => Number.isInteger(v) && v >= 0 && v <= max;

// Validates every numeric/list field of a request; returns a clean object or null.
function parseRequest(d) {
  const { mode, maxBytes, prefixLen, hintOffset, hintLen, allowedHints, expectedTotal } = d;
  if (mode !== 'probe' && mode !== 'full') return null;
  if (!isInt(maxBytes, HARD_MAX) || maxBytes < 1) return null;
  if (!isInt(prefixLen, HEADER_LEN) || prefixLen < 1) return null;
  if (!isInt(hintOffset, HEADER_LEN) || !isInt(hintLen, HEADER_LEN) || hintLen < 2) return null;
  if (hintOffset + hintLen > prefixLen) return null;                  // hint must sit inside the header
  if (mode === 'probe' && prefixLen !== HEADER_LEN) return null;
  if (!Array.isArray(allowedHints) || allowedHints.length > 1100) return null;
  if (!allowedHints.every(h => typeof h === 'string' && h.length <= 4000)) return null;
  if (expectedTotal !== undefined && expectedTotal !== null && !isInt(expectedTotal, HARD_MAX)) return null;
  return { mode, maxBytes, prefixLen, hintOffset, hintLen, allowedHints: new Set(allowedHints),
           expectedTotal: expectedTotal ?? null };
}

const fail = (code, message) => Object.assign(new Error(message), { code });
const _dec = new TextDecoder();

// Version byte and sender hint of the first prefixLen bytes must be acceptable.
function checkHeader(head, req) {
  if (head[0] !== SIG_VERSION) throw fail('HINT_REJECTED', 'unsupported version byte');
  const hint = _dec.decode(head.subarray(req.hintOffset, req.hintOffset + req.hintLen));
  if (!hint.endsWith(':') || !req.allowedHints.has(hint.slice(0, -1)))
    throw fail('HINT_REJECTED', 'sender hint not allowed');
}

// Reads exactly `n` bytes (or fewer if the body ends); never more than `n`.
async function readExactly(resp, n) {
  const out = new Uint8Array(n);
  let got = 0;
  const reader = resp.body.getReader();
  try {
    while (got < n) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = Math.min(value.length, n - got);
      out.set(value.subarray(0, take), got);
      got += take;
      if (take < value.length) { got = n + 1; break; }   // body longer than requested
    }
  } finally { reader.cancel().catch(() => {}); }
  return { bytes: out, got };
}

async function probe(cdnUrl, req) {
  let resp;
  try {
    resp = await fetch(cdnUrl, { cache: 'no-store', headers: { Range: `bytes=0-${HEADER_LEN - 1}` } });
  } catch (e) { throw fail('FETCH_FAILED', 'probe fetch failed'); }
  // Standard: RFC 9110 §14.4, Content-Range; deliberately rejects "/*" because the size gate needs a numeric complete-length
  const m = /^bytes 0-(\d+)\/(\d+)$/.exec(resp.headers.get('content-range') ?? '');
  if (resp.status !== 206 || !m || Number(m[1]) !== HEADER_LEN - 1) {
    resp.body?.cancel().catch(() => {});
    throw fail('NOT_RANGEABLE', `probe answered ${resp.status}`);
  }
  const total = Number(m[2]);
  if (!Number.isSafeInteger(total)) { resp.body?.cancel().catch(() => {}); throw fail('NOT_RANGEABLE', 'bad total'); }
  if (total > req.maxBytes) { resp.body.cancel().catch(() => {}); throw fail('TOO_LARGE', 'file too large'); }
  if (total <= HEADER_LEN) { resp.body.cancel().catch(() => {}); throw fail('TOO_SHORT', 'file too short'); }
  const { bytes, got } = await readExactly(resp, HEADER_LEN);
  if (got !== HEADER_LEN) throw fail('NOT_RANGEABLE', 'probe body length mismatch');
  checkHeader(bytes, req);
  return { totalBytes: total };
}

// Reuses one 256 KiB BYOB scratch buffer, then copies into a preallocated result: avoids per-chunk garbage.
// Reading directly into result detaches/re-wraps the large buffer per read, triggering major GCs.
const READ_SCRATCH_BYTES = 256 * 1024;

async function fetchFull(cdnUrl, req) {
  let resp;
  try { resp = await fetch(cdnUrl, { cache: 'no-store' }); }
  catch { throw fail('FETCH_FAILED', 'fetch failed'); }
  if (!resp.ok || !resp.body) { resp.body?.cancel().catch(() => {}); throw fail('FETCH_FAILED', `CDN fetch failed: ${resp.status}`); }

  const cap = req.expectedTotal !== null ? Math.min(req.maxBytes, req.expectedTotal) : req.maxBytes;
  const clRaw = resp.headers.get('content-length');
  // Standard: RFC 9110 §8.6, Content-Length = 1*DIGIT
  const cl = clRaw !== null && /^\d+$/.test(clRaw) ? Number(clRaw) : null;   // advisory only
  const reader = resp.body.getReader({ mode: 'byob' });
  const abort = (code, msg) => { reader.cancel().catch(() => {}); return fail(code, msg); };
  if (cl !== null && cl > cap) throw abort('TOO_LARGE', 'file too large');
  if (cl !== null && req.expectedTotal !== null && cl !== req.expectedTotal) throw abort('LENGTH_MISMATCH', 'object changed');

  // One allocation: the exact length when Content-Length is known, otherwise the cap.
  // The checks below keep total <= min(cap, cl), so every write fits, and the error codes match the chunked version.
  const size = cl ?? cap;
  let out;
  try { out = new Uint8Array(size); }
  catch { throw abort('FETCH_FAILED', 'could not allocate the download buffer'); }
  let scratch = new ArrayBuffer(Math.max(1, Math.min(READ_SCRATCH_BYTES, size)));   // BYOB needs a non-empty view
  let total = 0, checked = false;
  for (;;) {
    const { done, value } = await reader.read(new Uint8Array(scratch));
    scratch = value.buffer;                       // BYOB detaches the buffer on every read: continue from the returned one
    if (done) break;
    if (total + value.length > cap) throw abort('TOO_LARGE', 'file too large');
    if (cl !== null && total + value.length > cl) throw abort('LENGTH_MISMATCH', 'longer than Content-Length');
    out.set(value, total);
    total += value.length;
    if (!checked && total >= req.prefixLen) {
      try { checkHeader(out.subarray(0, req.prefixLen), req); } catch (e) { reader.cancel().catch(() => {}); throw e; }
      checked = true;
    }
  }
  if (!checked) throw fail('TOO_SHORT', 'file too short');
  if (req.expectedTotal !== null && total !== req.expectedTotal) throw fail('LENGTH_MISMATCH', 'object changed');
  if (cl !== null && total !== cl) throw fail('LENGTH_MISMATCH', 'shorter than Content-Length');
  // Without Content-Length (text path) the cap-sized buffer is trimmed to the bytes received.
  return { buffer: total === out.buffer.byteLength ? out.buffer : out.buffer.transfer(total), totalBytes: total };
}

// ── Lottie sticker JSON ──────────────────────────────────────────────────────

// Public, unencrypted animation data served by Discord's own CDN. Only this exact URL shape is
// fetched, rebuilt by content.js from a validated sticker id; this is not a general-purpose fetch.
// No size cap: the URL is only ever Discord's own CDN, and the id rides in a size-limited encrypted message.
// KEEP IN SYNC (content.js LOTTIE_URL_RE).
const LOTTIE_URL_RE = /^https:\/\/cdn\.discordapp\.com\/stickers\/\d{17,20}\.json$/;

async function fetchLottie(cdnUrl) {
  if (!LOTTIE_URL_RE.test(cdnUrl)) throw fail('BAD_REQUEST', 'not a Lottie sticker URL');
  let resp, buffer;
  try {
    resp = await fetch(cdnUrl, { cache: 'no-store', credentials: 'omit' });
    if (resp.ok) buffer = await resp.arrayBuffer();
  } catch { throw fail('FETCH_FAILED', 'fetch failed'); }
  if (!resp.ok) throw fail('FETCH_FAILED', `CDN fetch failed: ${resp.status}`);
  if (buffer.byteLength === 0) throw fail('FETCH_FAILED', 'empty sticker response');
  return { buffer, totalBytes: buffer.byteLength };
}

addEventListener('message', (e) => {
  if (port) return;                                           // one-shot
  if (e.source !== window.parent) return;
  const d = e.data;
  if (d?.type !== 'AGE_BRIDGE_INIT' || !secret || d.secret !== secret) return;
  if (e.ports.length !== 1) return;
  port = e.ports[0];
  port.onmessage = onRequest;
  port.postMessage({ type: 'AGE_BRIDGE_READY' });
});

async function onRequest(e) {
  const { type, requestId, cdnUrl } = e.data ?? {};
  if (type !== 'AGE_FETCH_RAW' && type !== 'AGE_FETCH_LOTTIE') return;
  // requestId is opaque here: it is only echoed back.
  // content.js owns its format and matching; an id it does not know is ignored there.
  const req = type === 'AGE_FETCH_RAW' ? parseRequest(e.data) : null;
  if (type === 'AGE_FETCH_RAW' && !req) return; // malformed numeric fields: ignored

  // cdnUrl is echoed in EVERY reply: content.js ignores a reply whose URL is not the one it asked for.
  function reply(payload) {
    port.postMessage({ type: 'AGE_FETCH_RAW_RESULT', requestId, cdnUrl, ...payload },
      payload.buffer ? [payload.buffer] : []);
  }

  try {
    if (!cdnUrl || typeof cdnUrl !== 'string')
      throw fail('BAD_REQUEST', `${type}: cdnUrl missing`);
    // cache: 'no-store' in both fetches — the ArrayBuffer is transferred (neutered) to content.js;
    // a cached response would return an ArrayBuffer(0) on the second fetch.
    reply(type === 'AGE_FETCH_LOTTIE' ? await fetchLottie(cdnUrl)
        : req.mode === 'probe'        ? await probe(cdnUrl, req)
        :                               await fetchFull(cdnUrl, req));
  } catch (err) {
    // Expected refusals (old/unknown sender key, size limits) are info; network/server trouble is warn;
    // anything else (incl. BAD_REQUEST) is a real bug.
    const c = err?.code;
    const log = ['HINT_REJECTED', 'TOO_LARGE', 'TOO_SHORT'].includes(c) ? console.info
              : ['FETCH_FAILED', 'NOT_RANGEABLE', 'LENGTH_MISMATCH'].includes(c) ? console.warn
              : console.error;
    log(`[age-iframe] ${type} ${c ?? 'error'} requestId=${requestId}:`, err?.message ?? err);
    reply({ code: err?.code ?? 'FETCH_FAILED', error: err?.message ?? String(err) });
  }
}
