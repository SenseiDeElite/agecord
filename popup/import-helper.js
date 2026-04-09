'use strict';

const statusEl = document.getElementById('status');

function setStatus(msg, cls) {
  statusEl.textContent = msg;
  statusEl.className = cls || '';
}

document.getElementById('f').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  setStatus('Reading file\u2026');
  try {
    const text = await file.text();

    const parsed = JSON.parse(text);
    const entries = Array.isArray(parsed) ? parsed : parsed && parsed.contacts;
    if (!Array.isArray(entries)) throw new Error('Not a valid contacts export.');

    setStatus('Saving\u2026');

    // Store this tab's ID alongside the JSON so the popup can close this tab
    // once the user dismisses the import result modal.
    const tabId = await new Promise(function(res) {
      chrome.tabs.getCurrent(function(tab) { res(tab ? tab.id : null); });
    });

    await new Promise(function(res, rej) {
      chrome.storage.session.set({ pending_import: text, pending_import_tab: tabId }, function() {
        if (chrome.runtime.lastError) rej(chrome.runtime.lastError);
        else res();
      });
    });

    // Chrome 127+ supports openPopup() from a tab page (user gesture context).
    // Firefox does not support it. In both cases we leave the tab open — the
    // popup will close it automatically when the user clicks OK in the result
    // modal, or when the popup is dismissed.
    try {
      await chrome.action.openPopup();
      setStatus('Done. The extension has reopened.', 'ok');
    } catch (_) {
      setStatus('Done. Click the extension icon to apply the import.', 'ok');
    }

  } catch (err) {
    setStatus('Error: ' + (err && err.message ? err.message : 'Unknown error'), 'err');
  }
});
