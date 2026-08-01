<p align="center">
  <img src="/icons/icon-512.svg" alt="Agecord logo" width="120" />
</p>

<h1 align="center">Agecord</h1>
<p align="center">
    We added encryption to Discord because
    <a href="https://cybernews.com/privacy/discord-voice-video-calls-private-text-messages/#:~:text=%E2%80%9CWe,challenge%2E%20%E2%80%9D">they wouldn't.</a>
</p>

<p align="center">
  A MV3 browser extension that adds <b>end-to-end post-quantum age encryption</b> to Discord.
  <br/>Messages are <b>encrypted</b> on your device before being sent —
  <br/>Discord's servers only see <b>ciphertext.</b>
</p>

<p align="center">
  <a href="https://addons.mozilla.org/en-US/firefox/addon/agecord/"><img src="https://img.shields.io/amo/v/agecord?style=for-the-badge&color=ffb877&labelColor=6b3a00&logo=firefoxbrowser&logoColor=white" alt="Mozilla Add-on" /></a>&nbsp;<a href="https://github.com/SenseiDeElite/agecord/blob/main/LICENSE"><img src="https://img.shields.io/github/license/SenseiDeElite/agecord?style=for-the-badge&color=ffffff&labelColor=333333&logo=gnu&logoColor=white" alt="License: GPLv3" /></a>&nbsp;<a href="https://github.com/SenseiDeElite/agecord/releases/latest"><img src="https://img.shields.io/badge/Chromium-Download-aac7ff?style=for-the-badge&labelColor=0a305f&logo=googlechrome&logoColor=white" alt="Chromium: Download" /></a>
</p>

### ✨ Features

- 🔒 **End-to-end encryption –** Messages are encrypted on the sender’s device and decrypted only on recipients’ devices.
- ✍️ **Digital signatures –** Messages are signed using public-key cryptography, providing authenticity and non-repudiation.
- 🔐 **Passphrase protection –** Encryption keys are unlocked with your passphrase for each session.
- ⚛️ **Post-quantum cryptography –** Uses ML-KEM-768×X25519 hybrid key encapsulation for quantum-resistant key exchange.
- 🦀 **Memory-safe algorithms –** Rust-based implementations of ML-DSA-87, Argon2id, XChaCha20-Poly1305, and SHAKE256 compiled to WebAssembly via [rustcrypto-wasm](https://github.com/SenseiDeElite/agecord/tree/main/rustcrypto-wasm).

---

### 🔐 Cryptography

Encryption uses [age](https://github.com/FiloSottile/typage) (ML-KEM-768×X25519 hybrid key agreement + ChaCha20-Poly1305), a modern and well-audited encryption format. Each message is also signed with an ML-DSA-87 signature, which guarantees that a message could only have been sent by the person who owns that keypair – any tampering or forgery is flagged immediately.

Your data is stored encrypted at rest on your device using Argon2id + XChaCha20-Poly1305. It is never uploaded anywhere.

**✉️ Message format**

Encrypted messages are sent as Discord file attachments (`.age` files). Each file begins with a version byte, followed by an ML-DSA-87 signature, a sender public-key hint, and the age ciphertext. The signature input binds a channelId (and serverId for servers) to prevent cross-channel replay. Messages are encrypted to all recipients and the sender, so the relevant parties can read the conversation.

**🫆 Key fingerprints**

Each contact's public key is displayed as a SHAKE256 (64-byte output) fingerprint. You can verify a contact's key out-of-band by comparing fingerprints with them directly if you wish.

**🚧 Limitations**

> ❌ **No forward secrecy.** If your private key is ever compromised, past messages encrypted to it could be read. Keep your passphrase strong and your private key safe.

> 🔏 **No age compatibility.** Agecord uses a custom message format to provide additional security properties within a instant messaging software, making its encrypted files incompatible with standard age tooling.

---

### ℹ️ Usage

See [`USAGE.md`](https://github.com/SenseiDeElite/agecord/blob/main/USAGE.md).

---

### 🔧 Troubleshooting

See [`TROUBLESHOOTING.md`](https://github.com/SenseiDeElite/agecord/blob/main/TROUBLESHOOTING.md).

---

### 📜 Third-Party Notices

See [`NOTICES.md`](https://github.com/SenseiDeElite/agecord/blob/main/NOTICES.md) for the third-party notices.

Not affiliated with Discord Inc. Research project, use at your own risk.
