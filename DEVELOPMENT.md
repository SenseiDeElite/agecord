## DEVELOPMENT

### Reproducibility

To reproduce the [libraries](https://github.com/SenseiDeElite/discord-age-encryption/tree/main/lib), follow the steps below.

**typage**

"A TypeScript implementation of the age file encryption format, available as an npm package or as a bundled .js file."

- First, download the desired version, which is generally the [latest release](https://github.com/FiloSottile/typage/releases/latest).
- Upon unpacking it, create a `entry.js` inside the extracted folder:
  ```js
  // entry.js
  export { Encrypter, Decrypter } from 'age-encryption';
  ```
- After that, run `npm ci` and `npm run build`.
- For bundling, use [esbuild](https://github.com/evanw/esbuild):
  ```sh
  esbuild entry.js \
  --bundle \
  --minify \
  --format=esm \
  --outfile=age.min.js
  ```

**awasm-noble**

"Auditable WASM implementation of cryptographic hashes & ciphers"

- First, download the desired version, which is generally the [latest release](https://github.com/paulmillr/awasm-noble/releases/latest).
- Upon unpacking it, create a `entry.js` inside the extracted folder:
  ```js
  // entry.js
  export { argon2id, xchacha20poly1305, blake3 } from './targets/wasm/index.js';
  ```
- After that, run `npm ci` and `npm run build`.
- For bundling, use [esbuild](https://github.com/evanw/esbuild):
  ```sh
  esbuild entry.js \
  --bundle \
  --minify \
  --format=esm \
  --outfile=awasm-noble.min.js
  ```

After finishing, move them inside [/lib/](https://github.com/SenseiDeElite/discord-age-encryption/tree/main/lib).

For their respective licenses, see [THIRD_PARTY_NOTICES.txt](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/THIRD_PARTY_NOTICES.txt).

---

## Packaging

**Chromium**

- Download the [latest release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest);
- Unpack it;
- Remove unneeded files for this build: `/icons/icon.svg`, `manifest-firefox.json`, `README.md` and `updates.json`;
- Rename `manifest-chromium.json` to `manifest.json`;
- Zip everything inside the folder.

**Firefox**

- Download the [latest release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest);
- Unpack it;
- Remove unneeded files for this build: `manifest-chromium.json` and `README.MD`;
- Rename `manifest-firefox.json` to `manifest.json`;
- Zip everything inside the folder;
- Rename the file extension to `.xpi`.
