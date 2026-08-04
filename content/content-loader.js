/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// content-loader.js — Classic-script shim for content.js

// Loads the ESM entry via dynamic import().

'use strict';

(async () => {
  await import(chrome.runtime.getURL('content/content.js'));
})();
