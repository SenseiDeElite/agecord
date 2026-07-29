# Usage Guide

This guide covers every screen and action available in the extension popup.

## First Time Setup

1. Click the extension icon in your toolbar.
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols).
3. Click **Generate keypair** to create and locally store your keys.
4. Open **My public key** and click **Copy** to share your public key with a contact.

## Unlocking the Extension

If the extension is locked, you will see the **Unlock extension** screen.

1. Enter your current passphrase in the **Passphrase** field.
2. Click **Unlock** to decrypt your local keypair and contacts for the session.

If you do not remember your passphrase and want to start fresh, click **Set up new keypair instead**. This opens the **Erase everything?** confirmation dialog:

- This permanently deletes your keypair and all contacts.
- Encrypted messages become unreadable forever unless you have a backup.
- Only proceed if you have forgotten your passphrase.
- Type `CONFIRM` in the text field, then click **Erase & start over**. Click **Cancel** to back out instead.

## Main Popup

Once unlocked, the main popup shows:

- **Encryption & Decryption** toggle at the top, which turns the extension's message interception and decryption on or off.
- A **Contacts** list with a search field and import/export icons.
- Each contact, group, or server entry displays its name and an **Encrypted** status badge.
- A **+ Add** button at the bottom to add a new recipient.
- Toolbar icons in the top right for **My public key** (key icon), **Lock session** (lock icon), and **About** (info icon).

## My Public Key Page

Open this page from the key icon in the main popup.

- **Public key** box displays your full public key, with a **Copy** button to copy it to your clipboard for sharing.
- **SHAKE256 fingerprint** shows a 64-byte fingerprint of your public key, broken into groups for easy comparison. Verify a contact's key out-of-band by comparing fingerprints directly with them.

### Advanced Options

Below the fingerprint, an **Advanced** section provides:

**Change passphrase**
1. Enter your **Current passphrase**.
2. Enter a **New passphrase** and repeat it in **Confirm new passphrase**.
3. Click **Change passphrase**. Your data is re-encrypted with the new passphrase. Click **Cancel** to back out.

**Export private key**
1. Enter your **Unlock passphrase**.
2. Enter a separate **Export passphrase** and repeat it in **Confirm export passphrase**. The exported blob is encrypted with Argon2id and XChaCha20-Poly1305 using this export passphrase.
3. Click **Encrypt & show** to reveal the encrypted export blob, or **Cancel** to back out.
4. Store both the encrypted blob and the export passphrase in a trusted password manager.

**Regenerate keypair**
1. Click **Regenerate keypair**.
2. A confirmation dialog warns that this creates a new keypair, all previous encrypted messages become unreadable, and contacts are disabled.
3. Type `CONFIRM` and click **Regenerate** to proceed, or **Cancel** to back out.

**Clear storage**
1. Click **Clear storage**.
2. A confirmation dialog warns that this permanently deletes your keypair and all contacts, and that encrypted messages become unreadable without a backup.
3. Type `CONFIRM` and click **Erase & start over** to proceed, or **Cancel** to back out.

## Adding a Recipient

Click **+ Add** from the main popup to open the **Add** screen. Choose a **Type** from the dropdown: **Contact**, **Group**, or **Server**.

### Adding a Contact

1. Set **Type** to **Contact**.
2. Paste the numerical **Channel ID** (found in the Discord URL as `discord.com/channels/@me/CHANNEL_ID`).
3. Enter a **Name** for the contact.
4. Paste their **Public key**.
5. Click **Save**.

### Adding a Group

1. Set **Type** to **Group**.
2. Paste the **Group ID** (found in the Discord URL as `discord.com/channels/@me/CHANNEL_ID`).
3. Enter a **Name** for the group.
4. In the **Select members** panel, use the search field to find existing contacts, then check each contact who should be able to receive encrypted messages in that group.
5. Click **Done**, then **Save**.

### Adding a Server

1. Set **Type** to **Server**.
2. Paste the **Server ID** (found in the Discord URL as `discord.com/channels/SERVER_ID/CHANNEL_ID`).
3. Enter a **Name** for the server.
4. In the **Select members** panel, use the search field to find existing contacts, then check each contact who should be able to receive encrypted messages in that server.
5. Click **Done**, then **Save**.

All sides need to have added each other before encrypted messaging works correctly.

## Importing Contacts

1. Open the import icon (upload arrow) from the main popup Contacts section.
2. On the **Import Contacts** screen, click **Choose file**.
3. Select your `agecord` contacts JSON export file.

Use the corresponding export icon (download arrow) in the main popup to export your current contacts to a JSON file.

## Managing an Existing Contact

Click a contact entry in the main popup list to open its detail card, which shows:

- The contact's name and **SHAKE256 fingerprint**.
- An **Encrypt to this contact** toggle, to enable or disable encryption for that specific recipient without toggling global encryption.
- **Edit contact** to open the **Edit Contact** screen, where you can update the **Channel ID**, **Contact name**, and **Public key**, then click **Save changes**.
- **Delete contact** to open a confirmation dialog. Confirm by clicking **Delete**, or click **Cancel** to back out. Deleting removes the contact's name and public key permanently.
- **Close** to return to the main popup without making changes.

## Sending Messages

1. Make sure the recipient, group, or server has been added and encryption is enabled for them.
2. Type your message in Discord as normal and press **Enter**. The extension intercepts and encrypts the message before sending.
3. Press **Enter** again to confirm sending.

Encrypted messages are sent as `.age` file attachments in Discord.

## Receiving Messages

Received encrypted messages are automatically decrypted and shown inline in Discord with a lock badge, provided the sender has been added as a contact with a matching public key.

## Toggling Encryption

Use the **Encryption & Decryption** switch at the top of the main popup to enable or disable the extension's interception and decryption behavior globally without affecting your stored keys or contacts.

## About Page

Open the About page from the info icon in the main popup. It displays:

- The extension name and current version.
- A **Source code** link to the GitHub repository.
- The **License** (GNU General Public License v3.0).
- A link to **Notices**, covering third-party attributions.
