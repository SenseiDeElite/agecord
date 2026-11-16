/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

'use strict';

// Equal to the storage.session quota used for the hand-off; same limit as popup.js.
const IMPORT_SIZE_LIMIT = 10 * 1024 * 1024;   // KEEP IN SYNC (popup.js)

const statusEl = document.getElementById('status');
const sealEl   = document.getElementById('seal');

function setStatus(msg, cls) {
  statusEl.textContent = msg;
  statusEl.className = cls ? `status ${cls}` : 'status';
  sealEl.classList.toggle('is-lit',    cls === 'ok');
  sealEl.classList.toggle('is-done',   cls === 'ok');
  sealEl.classList.toggle('is-danger', cls === 'err');
}
document.getElementById('f').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  setStatus('Reading file\u2026');
  try {
    // Check the size BEFORE reading anything into memory.
    if (file.size > IMPORT_SIZE_LIMIT)
      throw new Error(`File too large — contacts exports must be under ${(IMPORT_SIZE_LIMIT / 1024 / 1024).toFixed(1)} MiB.`);
    const text = await file.text();
    // Minimal sanity check: must be parseable JSON with an object at root.
    // Full v2 validation happens in the popup's doImportContacts().
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error('Not valid JSON.'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Not a valid contacts export.');
    }
    setStatus('Saving\u2026');
    // Store tab ID so the popup can close this tab after the import result is dismissed.
    // getCurrent() returns undefined (not null) outside a tab context.
    const tab   = await browser.tabs.getCurrent();
    const tabId = tab?.id ?? null;

    await browser.storage.session.set({ pending_import: text, pending_import_tab: tabId });

    await browser.action.openPopup();
    setStatus('Done. The extension has reopened.', 'ok');
  } catch (err) {
    setStatus('Error: ' + (err && err.message ? err.message : 'Unknown error'), 'err');
  }
});
