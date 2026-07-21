## DEVELOPMENT

### Reproducibility

**Build environment:** [Arch Linux](https://archlinux.org/)

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

### Third-Party Notices
 
Everything pulled in by `rustcrypto-wasm` (including transitive dependencies) is generated with [cargo-about](https://github.com/EmbarkStudios/cargo-about).
 
- From `rustcrypto-wasm/`, an `about.toml` controls which SPDX licenses are allowed to appear in the output. Add the reported license identifier to the accepted list:

```toml
accepted = [
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "Unicode-3.0",
]
```
 
- Generate the notices:
```sh
cargo about generate about.hbs > THIRD_PARTY_NOTICES.html
```
 
  This produces an HTML report of every crate in the resolved dependency tree, grouped by license text.
 
- `THIRD_PARTY_NOTICES.html` is an intermediate file, not a shipped artifact. It gets folded into two places:
  - **[`NOTICES.md`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/NOTICES.md)** — Markdown notices for the repository.
  - **`licenses.html`** — the bundled page the extension's `About` screen links to.

---

## Packaging

Packaging is handled by [`build.sh`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/build.sh).

1. Download the [latest release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest) source code;
2. Extract it;
3. From the extracted directory, run one of:

```sh
./build.sh chromium   # -> discord-age-encryption.crx
./build.sh firefox    # -> discord-age-encryption.xpi
./build.sh source     # -> discord-age-encryption.zip
```
