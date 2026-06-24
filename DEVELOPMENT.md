## DEVELOPMENT

### Reproducibility

To reproduce the [libraries](https://github.com/SenseiDeElite/discord-age-encryption/tree/main/lib), follow the steps below.

[**typage**](https://github.com/FiloSottile/typage)

*"A TypeScript implementation of the age file encryption format, available as an npm package or as a bundled .js file."*

- Download the expected version. We generally bundle the [latest release](https://github.com/FiloSottile/typage/releases/latest).
- Upon unpacking it, create a `entry.js` inside the extracted folder:
  
```js
export { Encrypter, Decrypter, generateHybridIdentity, identityToRecipient } from 'age-encryption';
```
  
- After that, run:

```sh
npm ci --ignore-scripts && npm run build
```

- For bundling, use [esbuild](https://github.com/evanw/esbuild):
  
```sh
esbuild entry.js \
      --bundle \
      --format=esm \
      --minify \
      --charset=utf8 \
      --tree-shaking=true \
      --outfile=age.min.js
```
  
[**Rust Crypto**](https://github.com/RustCrypto)

*"Cryptographic algorithms written in pure Rust"*

- Our project provides [rustcrypto-wasm](https://github.com/SenseiDeElite/discord-age-encryption/rustcrypto-wasm), a WebAssembly wrapper around RustCrypto implementations of [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2), [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305), [SHAKE256](https://github.com/RustCrypto/XOFs/tree/master/shake), and [ML-DSA-87](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), built by compiling native Rust code to WebAssembly.
- Make dependencies: [wasm-pack](https://github.com/wasm-bindgen/wasm-pack), [rust](https://github.com/rust-lang/rust) (including rust-wasm), [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) and [binaryen](https://github.com/WebAssembly/binaryen).
- Upon obtaining them, run:

```sh
wasm-pack build --target web --release
```

- For bundling, use [esbuild](https://github.com/evanw/esbuild):
  
```sh
esbuild entry.js \
      --bundle \
      --format=esm \
      --minify \
      --charset=utf8 \
      --tree-shaking=true \
      --loader:.wasm=binary \
      --outfile=rustcrypto-wasm.min.js
```

After finishing, move the libraries to [/lib/](https://github.com/SenseiDeElite/discord-age-encryption/tree/main/lib).

For their respective licenses, see [`NOTICES.md`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/NOTICES.md).

---

## Packaging

**Chromium**

1. Download the [latest release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest) source code;
2. Extract it;
3. Remove unnecessary files for this build: `/icons/icon.svg`, `manifest-firefox.json`, `README.md`, `DEVELOPMENT.md`, `updates.json`, `updates.xml` and `/rustcrypto-wasm/`;
4. Rename `manifest-chromium.json` to `manifest.json`;
5. Navigate to `chrome://extensions/`;
6. Enable `Developer mode` (if not already done);
7. Click `Pack extension`;
8. Browse to the extension root directory;
9. Select a private key file or don't to generate one in the next step.
10. Click `Pack extension` again; a `.crx` file will be generated.

**Firefox**

1. Download the [latest release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest) source code;
2. Extract it;
3. Remove unnecessary files for this build: `manifest-chromium.json`, `DEVELOPMENT.md`, `README.md`, `updates.json`, `updates.xml` and `/rustcrypto-wasm/`;
4. Rename `manifest-firefox.json` to `manifest.json`;
5. Zip everything inside the folder;
6. Rename the file extension to `.xpi`.
