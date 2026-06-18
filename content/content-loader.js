// content-loader.js — Classic-script shim for content.js
//
// Manifest content_scripts don't support "type": "module", so this classic
// script uses dynamic import() (Chrome / Firefox 89+) to load the real ESM.
// content.js and its dependencies must be listed in web_accessible_resources.

'use strict';

(async () => {
  await import(chrome.runtime.getURL('content/content.js'));
})();
