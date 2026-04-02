## Discord Age Encryption

A browser extension that adds end-to-end encrypted messaging to Discord DMs. Messages are encrypted on your device before being sent — Discord's servers only see ciphertext.

---

### Features

- 🔒 **End-to-end encrypted —** only you and your contact can read messages;
- ✍️ **Signed messages —** every message is cryptographically signed, preventing tampering;
- 🔑 **Your keys, your device —** private keys never leave your machine;
- 🔐 **Passphrase protected —** your private key is encrypted at rest, unlocked per session.

---

### Cryptography

Encryption uses [age](https://github.com/FiloSottile/typage) (X25519 key agreement + ChaCha20-Poly1305), a modern and well-audited encryption format. Each message is also signed with an Ed25519 signature, which guarantees that a message could only have been sent by the person who owns that keypair — any tampering or forgery is flagged immediately.

Your private key is stored encrypted on your device using age's scrypt passphrase protection. It is never uploaded anywhere.

**Wire format**

Encrypted messages are sent as raw ciphertext, prefixed with `[age]` so the extension can identify them. Each message embeds a short random ID, the ciphertext, and an Ed25519 signature — all in a single self-contained string. Messages are encrypted to both the recipient and the sender, so both parties can read the conversation.

**Key fingerprints**

Each contact's public key is displayed as a [BLAKE3](https://github.com/paulmillr/noble-hashes) (64-byte output) fingerprint. You can verify a contact's key out-of-band by comparing fingerprints with them directly, or by computing the checksum yourself. This is optional.

First, install b3sum according to your operating system. Commands assume b3sum is added to PATH.

**Arch Linux**

```bash
run0 pacman -Syu b3sum
```

**Cargo (cross-platform)**

```sh
cargo install b3sum
```

**BLAKE3 binaries**

See [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3/releases/latest).

Then, replace "age1..." with the actual age public key that you want to verify.

**Linux & macOS**

```sh
printf '%s' "age1..." | b3sum --length 64 | awk '{s=toupper($1); for(i=1;i<=length(s);i+=4) printf "%s%s", substr(s,i,4), (i+3)%32==0 ? "\n" : " "; print ""}'
```

**Windows**

```powershell
"age1..." | Out-File -Encoding utf8NoBOM tmp_key.txt; b3sum --length 64 --no-names tmp_key.txt | ForEach-Object { $h = $_.ToUpper(); 0..3 | ForEach-Object { $h.Substring($_*32,32) -replace '(.{4})(?!$)','$1 ' } | Write-Host }; Remove-Item tmp_key.txt
```

**Limitations**

> ⚠️ **No forward secrecy.** If your private key is ever compromised, past messages encrypted to it could be read. Keep your passphrase strong and your private key safe.

> ⚠️ **Not post-quantum secure.** The algorithms used (X25519, Ed25519, ChaCha20-Poly1305) are not resistant to attacks from a sufficiently powerful quantum computer. A future quantum adversary that recorded your encrypted messages today could potentially decrypt them later. age does support post-quantum algorithms, but the resulting ciphertext is too long for Discord, making it impractical for this use case.

---

### 🐛 Known Issues

Editing encrypted messages does not update the decrypted view. If you edit an already sent encrypted message, it'll continue to show the old decrypted content until you do a full page reload (`Ctrl+R`/`Cmd+R`). This is a limitation of how the extension hooks into Discord's React-based DOM and does not have a simple fix at this time. Contributions are welcome.

---

### Installation

#### Chromium & Firefox

See the latest [release](https://github.com/SenseiDeElite/discord-age-encryption/releases/latest). Only Firefox supports auto update for the time being.

---

### Getting started

**First time setup**

1. Click the extension icon in your toolbar;
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols);
3. Click **Generate keypair** — your keys are created and stored locally;
4. Click **My public key** and copy it to share with your contact.

**Adding a contact**

1. Open your contact DM in Discord;
2. Click **Add contact** in the extension;
3. Paste their public key and give them a identifiable name — the channel ID fills in automatically if you're already in their DM;
4. Click **Save contact**.

Both sides need to have added each other before encrypted messaging works correctly.

**Sending messages**

Once a contact is added and enabled, just type and press **Enter** — the extension intercepts the message and encrypts it. Received encrypted messages are decrypted and shown inline with a lock badge.

---

### Key management

- **Export private key —** requires passphrase re-entry. Save the exported blob somewhere safe (a password manager or encrypted vault). Anyone who has it can read and write encrypted messages on your behalf.
- **Regenerate keypair —** creates a new keypair. All previous encrypted messages become permanently unreadable and all contacts are disabled. Use only if your key is compromised.

---

### License

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

See [THIRD_PARTY_NOTICES.txt](https://github.com/SenseiDeElite/discord-age-encryption/blob/main/THIRD_PARTY_NOTICES.txt) for full third-party license texts.

This extension is not affiliated with or endorsed by Discord Inc. or any of the projects mentioned.
