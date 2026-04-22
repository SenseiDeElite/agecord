// content-loader.js — Classic-script shim for content.js
//
// Chrome and Firefox do not support static `import` in content scripts
// declared via manifest content_scripts (no "type": "module" key exists).
// The workaround: this tiny classic script is what the manifest loads;
// it immediately hands off to the real ESM module via dynamic import().
// Dynamic import() in content scripts is supported in Chrome and Firefox 89+.
//
// content.js and its dependencies (age.min.js, emoji_map.js) must be listed
// in web_accessible_resources so the extension can import() them by URL.

(async () => {
  await import(chrome.runtime.getURL('content/content.js'));
})();
