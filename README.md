<p align="center">
  <img src="/icons/icon.svg" alt="Discord Age Encryption logo" width="120" />
</p>

<h1 align="center">Discord Age Encryption</h1>

<p align="center">
  A browser extension that adds end-to-end <b>encrypted</b> messaging to <b>Discord.</b>
  <br/>Messages are <b>encrypted</b> on your device before being sent —
  <br/><b>Discord's</b> servers only see ciphertext.
</p>

<p align="center">
  <a href="https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPLv3" />
  </a>
</p>

### ⚙️ Features

- 🔒 **End-to-end encrypted –** only you and your recipients can read messages;
- ✍️ **Signed messages –** every message is cryptographically signed, proving authenticity;
- 🔑 **Your keys, your device –** private keys never leave your browser;
- 🔐 **Passphrase protected –** your data is encrypted at rest, unlocked per session.
- 🤫 **Modern cryptography –** Utilizes Argon2id, XChaCha20-Poly1305, BLAKE3 through [awasm-noble](https://github.com/paulmillr/awasm-noble) where appropriate.
- ⚡ **Lightning fast –** Messages are encrypted and decrypted almost instantly. WebCrypto API, hardware acceleration and WebAssembly are leveraged to deliver you a smooth experience.

---

### 🔐 Cryptography

Encryption uses [age](https://github.com/FiloSottile/typage) (X25519 key agreement + ChaCha20-Poly1305), a modern and well-audited encryption format. Each message is also signed with an Ed25519 signature, which guarantees that a message could only have been sent by the person who owns that keypair – any tampering or forgery is flagged immediately.

Your data is stored encrypted at rest on your device using Argon2id + XChaCha20-Poly1305. It is never uploaded anywhere.

**🪡 Wire format**

Encrypted messages are sent as raw ciphertext, prefixed with `[age]` so the extension can identify them. Each message embeds a serverId (only for servers), channelId (to prevent cross-channel replay), the ciphertext, and an Ed25519 signature – all in a single self-contained string. Messages are encrypted to all recipients and the sender, so the relevant parties can read the conversation.

**🫆 Key fingerprints**

Each contact's public key is displayed as a BLAKE3 (128-byte output) fingerprint. You can verify a contact's key out-of-band by comparing fingerprints with them directly if you wish.

**🚧 Limitations**

> ❌ **No forward secrecy.** If your private key is ever compromised, past messages encrypted to it could be read. Keep your passphrase strong and your private key safe.

> 🔓 **Not post-quantum secure.** The majority of the algorithms used are not resistant to harvest now, decrypt later (HNDL) attacks. A future quantum adversary that recorded your encrypted messages today could potentially decrypt them later. age does support post-quantum algorithms, but the resulting ciphertext is too long for Discord, making it impractical for this use case.

---

### ⬇️ Installation

#### 🦊 Chromium & Firefox

See the latest [release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest). Only Firefox supports auto update for the time being.

**🔧 Troubleshooting**

v0.4.0+ requires WebAssembly. Make sure you didn't disable it through browser hardening.

Chromium: `DefaultJavaScriptJitSetting` policy.

Firefox: `javascript.options.wasm` preference (`about:config`).

---

### ▶️ Getting started

**🛠️ First time setup**

1. Click the extension icon in your toolbar;
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols);
3. Click **Generate keypair** – your keys are created and stored locally;
4. Click **My public key** and copy it to share with your contact.

**➕ Adding a recipient**

1. Open a contact, group or server in Discord;
2. Click **+ Add** in the extension;
3. Fill in the required details;
4. Click **Save** once done.

All sides need to have added each other before encrypted messaging works correctly.

**📩 Sending messages**

Once a given recipient is added and enabled, just type your message and press **Enter** – the extension intercepts and encrypts it before sending. Hit enter again to confirm.

If Discord warns you that the message you are about to send might contain a Discord token, this is a side effect of the characters present in the message. You can safely ignore it and hit enter again – the extension never sends any secrets anywhere.

Received encrypted messages are decrypted and shown inline with a lock badge.

---

### 📄 Licenses

[GNU General Public License v3.0](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE)

See [`THIRD_PARTY_NOTICES.txt`](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/THIRD_PARTY_NOTICES.txt) for full third-party license texts.

This extension is not affiliated with nor endorsed by Discord Inc.
