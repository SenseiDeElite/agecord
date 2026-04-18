## Discord Age Encryption

A browser extension that adds end-to-end encrypted messaging to Discord. Messages are encrypted on your device before being sent — Discord's servers only see ciphertext.

---

### Features

- 🔒 **End-to-end encrypted —** only you and your contacts can read messages;
- ✍️ **Signed messages —** every message is cryptographically signed, preventing tampering;
- 🔑 **Your keys, your device —** private keys never leave your machine;
- 🔐 **Passphrase protected —** your private key is encrypted at rest, unlocked per session.

---

### Cryptography

Encryption uses [age](https://github.com/FiloSottile/typage) (X25519 key agreement + ChaCha20-Poly1305), a modern and well-audited encryption format. Each message is also signed with an Ed25519 signature, which guarantees that a message could only have been sent by the person who owns that keypair — any tampering or forgery is flagged immediately.

Your private key is stored encrypted on your device using [Argon2id + XChaCha20-Poly1305](https://github.com/paulmillr/awasm-noble). It is never uploaded anywhere.

Cryptographic operations utilize WebAssembly and follow RFCs whenever possible, making them secure and fast.

**Wire format**

Encrypted messages are sent as raw ciphertext, prefixed with `[age]` so the extension can identify them. Each message embeds a bindingId (to prevent cross-channel replay), the ciphertext, and an Ed25519 signature — all in a single self-contained string. Messages are encrypted to both the recipients and the sender, so both parties can read the conversation.

**Key fingerprints**

Each contact's public key is displayed as a BLAKE3 (128-byte output) fingerprint. You can verify a contact's key out-of-band by comparing fingerprints with them directly.

**Limitations**

> ⚠️ **No forward secrecy.** If your private key is ever compromised, past messages encrypted to it could be read. Keep your passphrase strong and your private key safe.

> ⚠️ **Not post-quantum secure.** The algorithms used (X25519, Ed25519, ChaCha20-Poly1305) are not resistant to attacks from a sufficiently powerful quantum computer. A future quantum adversary that recorded your encrypted messages today could potentially decrypt them later. age does support post-quantum algorithms, but the resulting ciphertext is too long for Discord, making it impractical for this use case.

---

### 🐛 Known Issues

Editing encrypted messages does not update the decrypted view. If you edit an already sent encrypted message, it'll continue to show the old decrypted content until you switch channels or reload the page. This is a limitation of how the extension hooks into Discord's React-based DOM and does not have a simple fix at this time. Contributions are welcome.

---

### Installation

#### Chromium & Firefox

See the latest [release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest). Only Firefox supports auto update for the time being.

v0.4.0+ requires WebAssembly. Make sure you didn't disable it through browser hardening.

Chromium: `DefaultJavaScriptJitSetting` policy.

Firefox: `javascript.options.wasm` preference. (about:config)

---

### Getting started

**First time setup**

1. Click the extension icon in your toolbar;
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols);
3. Click **Generate keypair** — your keys are created and stored locally;
4. Click **My public key** and copy it to share with your contact.

**Adding a contact**

1. Open a contact, group or server in Discord;
2. Click **+ Add** in the extension;
3. Follow on-screen instructions;
4. Click **Save contact**.

Both sides need to have added each other before encrypted messaging works correctly.

**Sending messages**

Once a contact is added and enabled, just type and press **Enter** — the extension intercepts the message and encrypts it. Received encrypted messages are decrypted and shown inline with a lock badge.

---

### Licenses

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE)

See [THIRD_PARTY_NOTICES.txt](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/THIRD_PARTY_NOTICES.txt) for full third-party license texts.

This extension is not affiliated with nor endorsed by Discord Inc.
