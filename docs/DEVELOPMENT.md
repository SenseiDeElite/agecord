## DEVELOPMENT

### Reproducibility

**Build environment:** [Arch Linux x86-64](https://archlinux.org/)

**Toolchain**: [npm v12.2.2](https://github.com/npm/cli/releases/tag/v12.2.2), [esbuild v0.28.2](https://github.com/evanw/esbuild/releases/tag/v0.28.2), [wasm-pack v0.15.1](https://github.com/wasm-bindgen/wasm-pack/releases/tag/v0.15.1), [rust 1.100.0](https://github.com/rust-lang/rust/releases/tag/1.100.0) (including rust-wasm target), [wasm-bindgen 0.2.130](https://github.com/wasm-bindgen/wasm-bindgen/releases/tag/0.2.130), [binaryen 130](https://github.com/WebAssembly/binaryen/releases/tag/version_130) and [LLVM 23.1.5](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.5).

To reproduce the [libraries](https://github.com/SenseiDeElite/agecord/tree/main/src/lib), follow the steps below.

[**typage**](https://github.com/FiloSottile/typage)

*"A TypeScript implementation of the age file encryption format, available as an npm package or as a bundled .js file."*

- Download [typage v0.3.1 source code](https://github.com/FiloSottile/typage/releases/tag/v0.3.1).
- Upon unpacking it, create a `entry.js` inside the extracted folder containing the following:
  
```js
export { Encrypter, Decrypter, generateHybridIdentity, identityToRecipient } from 'age-encryption';
```
  
- Make sure npm is installed, then run:

```sh
npm ci --ignore-scripts && npm run build
```

- For bundling, use esbuild:
  
```sh
esbuild entry.js \
      --bundle \
      --format=esm \
      --minify \
      --charset=utf8 \
      --tree-shaking=true \
      --outfile=age.min.js
```
  
[**Agecord-Wasm**](https://github.com/SenseiDeElite/agecord/tree/main/wasm)

*"WebAssembly Agecord protocol"*

- Our project provides the [`agecord`](https://github.com/SenseiDeElite/agecord/tree/main/wasm) crate, a WebAssembly wrapper around RustCrypto implementations of [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2), [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305), [SHAKE256](https://github.com/RustCrypto/XOFs/tree/master/shake), and [ML-DSA-87](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), built by compiling native Rust code to WebAssembly.
- Every exported function sits behind its own Cargo feature (the export name with `_` written as `-`), and nothing is enabled by default. Rather than shipping one module with everything in it, each part of the extension gets its own WASM module containing only the functions it imports.

- From [tools](https://github.com/SenseiDeElite/agecord/tree/main/tools), run:

```sh
./build-wasm.sh
```

  To build a single library, name it (e.g. `./build-wasm.sh sign`). For each library the script compiles the crate, generates the entry file and bundles it into [`lib/`](https://github.com/SenseiDeElite/agecord/tree/main/src/lib).

After finishing, move `age.min.js` (typage) to [lib/](https://github.com/SenseiDeElite/agecord/tree/main/src/lib). The `agecord-*.min.js` libraries are written there directly by the script.

### Packaging

Packaging is handled by [`build.sh`](https://github.com/SenseiDeElite/agecord/blob/main/tools/build.sh):

```sh
./build.sh chromium
./build.sh firefox
./build.sh source
```

### Third-Party Notices

From [wasm/](https://github.com/SenseiDeElite/agecord/tree/main/wasm), generate an intermediary file with [cargo-about](https://github.com/EmbarkStudios/cargo-about):
```sh
cargo about generate --all-features --locked --format json -o about.json
```
