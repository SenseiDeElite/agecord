## DEVELOPMENT

### Reproducibility

**Build environment:** [Arch Linux x86-64](https://archlinux.org/)

To reproduce the [libraries](https://github.com/SenseiDeElite/agecord/tree/main/lib), follow the steps below.

[**typage**](https://github.com/FiloSottile/typage)

*"A TypeScript implementation of the age file encryption format, available as an npm package or as a bundled .js file."*

- Download [typage v0.3.0 source code](https://github.com/FiloSottile/typage/releases/tag/v0.3.0).
- Upon unpacking it, create a `entry.js` inside the extracted folder:
  
```js
export { Encrypter, Decrypter, generateHybridIdentity, identityToRecipient } from 'age-encryption';
```
  
- Make sure [npm v12.0.2](https://github.com/npm/cli/releases/tag/v12.0.2) is installed, then run:

```sh
npm ci --ignore-scripts && npm run build
```

- For bundling, use [esbuild v0.28.2](https://github.com/evanw/esbuild/releases/tag/v0.28.2):
  
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

- Our project provides [rustcrypto-wasm](https://github.com/SenseiDeElite/agecord/tree/main/rustcrypto-wasm), a WebAssembly wrapper around RustCrypto implementations of [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2), [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305), [SHAKE256](https://github.com/RustCrypto/XOFs/tree/master/shake), and [ML-DSA-87](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), built by compiling native Rust code to WebAssembly.
- Make dependencies: [wasm-pack v0.15.0](https://github.com/wasm-bindgen/wasm-pack/releases/tag/v0.15.0), [rust 1.97.1](https://github.com/rust-lang/rust/releases/tag/1.97.1) (including rust-wasm target), [wasm-bindgen 0.2.127](https://github.com/wasm-bindgen/wasm-bindgen/releases/tag/0.2.127) and [binaryen 130](https://github.com/WebAssembly/binaryen/releases/tag/version_130).
- Upon obtaining them, run:

```sh
wasm-pack build --target web --release
```

- For bundling, use [esbuild v0.28.2](https://github.com/evanw/esbuild/releases/tag/v0.28.2):
  
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

After finishing, move the libraries to [/lib/](https://github.com/SenseiDeElite/agecord/tree/main/lib).

### Third-Party Notices
 
Everything pulled in by `rustcrypto-wasm` (including transitive dependencies) is generated with [cargo-about](https://github.com/EmbarkStudios/cargo-about):

```sh
cargo about init && cargo about generate about.hbs > THIRD_PARTY_NOTICES.html
```
 
  This produces an HTML report of every crate in the resolved dependency tree, grouped by license text.
 
- `THIRD_PARTY_NOTICES.html` is an intermediate file, not a shipped artifact. It gets folded into two places:
  - **[`NOTICES.md`](https://github.com/SenseiDeElite/agecord/blob/main/NOTICES.md)** — Markdown notices for the repository.
  - **`licenses.html`** — the bundled page the extension's `About` screen links to.

### Packaging

Packaging is handled by [`build.sh`](https://github.com/SenseiDeElite/agecord/blob/main/build.sh):

```sh
./build.sh chromium
./build.sh firefox
./build.sh source
```
