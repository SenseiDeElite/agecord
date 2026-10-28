## Troubleshooting

Make sure the following permissions are enabled in Firefox, or the extension won't work:
- `Access your data for https://discord.com`
- `Access your data for https://cdn.discordapp.com`

### Requirements

| Requirement | Chromium | Firefox |
|---|---|---|
| Minimum browser version | v155 | v159.0 |
| JPEG XL (v0.7.1) | v155 | v158.0 |
| Browser namespace (v0.7.4) | v148 | v109.0 |
| Scroll-driven animations (v0.9.0) | v115 | v159.0 |
| Corner shape (v0.9.0) | v139 | N/A |
| Animated SVG icon (v0.9.1) | N/A | v62.0 |


Compatibility can change at any time. Make sure your browser is up-to-date.

### "This extension is not listed in the Chrome Web Store and may have been added without your knowledge."

Some proprietary Chromium-based browsers may block installation of extensions that haven't gone through the CWS (Chrome Web Store) review.

This extension has been submitted to [AMO](https://addons.mozilla.org/en-US/firefox/addon/agecord/), but not to CWS, since it requires a $5 developer account creation fee. As this is a hobby project, I don't intend to pay for that. This restriction is unrelated to the extension's actual security.

If you trust the extension, you can bypass this check for it specifically, without needing to trust other extensions, by applying a browser policy:

1. Download [`policies.json`](https://github.com/SenseiDeElite/agecord/blob/main/policies.json) from this repository.
2. Download the latest release of [chromium-policies.json](https://github.com/SenseiDeElite/chromium-policies.json/releases/latest), my other project for applying Chromium policies.
3. Replace the `policies.json` from that project with the one downloaded in step 1.
4. Follow the [`README.md`](https://github.com/SenseiDeElite/chromium-policies.json#%EF%B8%8F-installation) instructions to apply the policy.
5. The extension should now be allowlisted automatically. If needed, repeat the normal installation steps.
