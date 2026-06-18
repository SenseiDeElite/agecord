<p align="center">
  <img src="/icons/icon.svg" alt="Discord Age Encryption logo" width="120" />
</p>

<h1 align="center">Discord Age Encryption</h1>
<p align="center">
    We added encryption to Discord because
    <a href="https://cybernews.com/privacy/discord-voice-video-calls-private-text-messages/#:~:text=%E2%80%9CWe,challenge%2E%20%E2%80%9D">they wouldn't.</a>
</p>

<p align="center">
  A MV3 browser extension that adds <b>post-quantum end-to-end encryption</b> to Discord.
  <br/>Messages are <b>encrypted</b> on your device before being sent —
  <br/>Discord's servers only see <b>ciphertext.</b>
</p>

<p align="center">
  <a href="https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPLv3" />
  </a>
</p>

### ✨ Features

- 🔒 **End-to-end encryption –** Messages are encrypted on the sender’s device and decrypted only on recipients’ devices.
- ✍️ **Digital signatures –** Messages are signed using public-key cryptography, providing authenticity and non-repudiation.
- 🔐 **Passphrase protection –** Encryption keys are unlocked with your passphrase for each session.
- ⚛️ **Post-quantum cryptography –** Uses ML-KEM-768×X25519 hybrid key encapsulation for quantum-resistant key exchange.
- 🦀 **Memory-safe algorithms –** Rust-based implementations of ML-DSA-87, Argon2id, XChaCha20-Poly1305, and SHAKE256 compiled to WebAssembly via [rustcrypto-wasm](https://github.com/SenseiDeElite/discord-age-encryption/rustcrypto-wasm).

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

---

### ⬇️ Installation

#### 🌐 Chromium & Firefox

See the latest [release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest). Only Firefox supports auto update for the time being.

**🔧 Troubleshooting**

**v0.4.0+** requires **WebAssembly**. Make sure you didn't disable it through browser hardening.

Chromium: `DefaultJavaScriptJitSetting` policy.

Firefox: `javascript.options.wasm` preference (`about:config`).

**v0.7.0+** requires **JPEG XL** support. Make sure it is enabled or **JXL** images will be rendered broken.

Chromium 145+: `#enable-jxl-image-format` flag (`chrome://flags/`).

Firefox 152+: `image.jxl.enabled` preference (`about:config`).

---

### 🏁 Getting started

**⚙️ First time setup**

1. Click the extension icon in your toolbar;
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols);
3. Click **`Generate keypair`** – your keys are created and stored locally;
4. Click **`My public key`** and copy it to share with your contact.

**➕ Adding a recipient**

1. Open a contact, group or server in Discord;
2. Click **`+ Add`** in the extension;
3. Fill in the required details;
4. Click **`Save`** once done.

All sides need to have added each other before encrypted messaging works correctly.

**📨 Sending messages**

Once a given recipient is added and enabled, just type your message and press **`Enter`** – the extension intercepts and encrypts it before sending. Hit enter again to confirm.

Received encrypted messages are decrypted and shown inline with a lock badge.

---

### 📄 Licenses

[`GNU General Public License v3.0`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE)

See [`NOTICES.md`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/NOTICES.md) for full third-party license texts.

Not affiliated with Discord Inc. Research project, use at your own risk.
