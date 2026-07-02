## Troubleshooting

> 🦊 This extension runs faster on Firefox.

Make sure the following permissions are enabled in Firefox, or the extension won't work:
- `Access your data for https://discord.com`
- `Access your data for https://cdn.discordapp.com`

### Requirements

| Requirement | Chromium | Firefox |
|---|---|---|
| Minimum browser version | v148+ | v152.0+ |
| WebAssembly (v0.4.0+) | `DefaultJavaScriptJitSetting` policy | `javascript.options.wasm` preference (`about:config`) |
| JPEG XL support (v0.7.1+) | `#enable-jxl-image-format` flag (`chrome://flags/`) | `image.jxl.enabled` preference (`about:config`) |
| Unified browser actions API (v0.7.4+) | Requires Chromium v148+ | v109.0 (initial support), v149.0 (relaxed user gesture requirements) |

- **WebAssembly:** required since v0.4.0. If disabled via browser hardening, the extension won't run — check the settings above.
- **JPEG XL:** required since v0.7.1. If disabled, JXL images will render broken.

Compatibility can change at any time. Make sure your browser is up-to-date.

### "This extension is not listed in the Chrome Web Store and may have been added without your knowledge."

Some proprietary Chromium-based browsers (mainly on Windows and macOS, but occasionally Linux) block installation of extensions that haven't gone through the Chrome Web Store (CWS) automated review.

This extension has been submitted to AMO (addons.mozilla.org), but not to CWS, since CWS review requires a $5 developer account fee. As this is a hobby project, I don't intend to pay for that. This restriction is unrelated to the extension's actual security.

If you trust the extension, you can bypass this check for it specifically, without needing to trust other unlisted extensions, by applying a browser policy:

1. Download [`policies.json`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/policies.json) from this repo.
2. Download the latest release of [chromium-policies.json](https://github.com/SenseiDeElite/chromium-policies.json/releases/latest), my other project for applying Chromium policies across major Chromium-based browsers and operating systems.
3. Replace the `policies.json` from that project with the one downloaded in step 1.
4. Follow the [`README.md`](https://github.com/SenseiDeElite/chromium-policies.json/blob/main/README.md) instructions to apply the policy.
5. The extension should now be allowlisted automatically. If it doesn't, repeat the normal installation steps.
