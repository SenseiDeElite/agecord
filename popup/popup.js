// popup.js — Discord Age Encryption
//
// Key storage : age identity (AGE-SECRET-KEY-1…) encrypted with a user passphrase,
//               stored as base64 in chrome.storage.local.
// Session     : decrypted identity is sent to background.js via SET_IDENTITY.
//               background.js holds it in memory and in chrome.storage.session.
//               Content scripts never receive the raw identity — they ask the
//               background to encrypt/sign/decrypt on their behalf.

(() => {
  'use strict';

  // ─── Storage helpers ────────────────────────────────────────────────────────
  const store = {
    get:    keys => new Promise(r => chrome.storage.local.get(keys, r)),
    set:    data => new Promise(r => chrome.storage.local.set(data, r)),
    remove: keys => new Promise(r => chrome.storage.local.remove(keys, r)),
  };

  // Send a fire-and-forget signal to all Discord tabs (RELOCK, CONTACTS_UPDATED).
  // UNLOCK is handled by background.js directly — it signals tabs itself after
  // SET_IDENTITY and also handles tab-reload unlock with retry logic.
  function sendToDiscordTabs(msg) {
    chrome.tabs.query({ url: 'https://discord.com/*' }, tabs => {
      for (const tab of tabs)
        chrome.tabs.sendMessage(tab.id, msg, () => void chrome.runtime.lastError);
    });
  }

  // Tell background.js about the identity (it stores it and imports the signing key),
  // then signal Discord tabs only after the background confirms it is ready.
  // Awaiting the response ensures applyIdentity() and session storage writes have
  // both completed before any DECRYPT request can arrive from a content script.
  async function setIdentityInBackground(identity) {
    await chrome.runtime.sendMessage({ type: 'SET_IDENTITY', identity });
    // Background confirmed ready — now safe to wake Discord tabs.
    sendToDiscordTabs({ type: 'UNLOCK' });
  }

  // Tell background.js to wipe the identity.
  async function clearIdentityInBackground() {
    await chrome.runtime.sendMessage({ type: 'CLEAR_IDENTITY' });
  }

  // ─── State ──────────────────────────────────────────────────────────────────
  let _contacts        = {};
  let _globalOn        = true;
  let _selectedId      = null;
  let _sessionIdentity = null;  // kept in popup memory for private key export only
  let _myKeyGeneration = 0;     // incremented on each showMyKey() call; guards stale async continuations

  // ─── Screen router ──────────────────────────────────────────────────────────
  const screens = ['lock', 'setup', 'import', 'main', 'add-contact', 'edit-contact', 'my-key', 'about'];
  const show = screenId =>
    screens.forEach(id => { document.getElementById(`screen-${id}`).hidden = (id !== screenId); });

  // ─── Session helpers ─────────────────────────────────────────────────────────
  // The popup reads session state from storage to know if already unlocked on boot.
  // All writes go through background.js (SET_IDENTITY / CLEAR_IDENTITY messages).

  async function getSessionIdentity() {
    try {
      if (chrome.storage.session) {
        const r = await new Promise(res => chrome.storage.session.get(['age_unlocked', 'age_identity'], res));
        return r.age_unlocked === true ? (r.age_identity ?? null) : null;
      }
    } catch {}
    return null;
  }

  // ─── Boot ───────────────────────────────────────────────────────────────────

  async function boot() {
    const data = await store.get(['ageRecipient', 'ageEncryptedIdentity', 'contacts', 'globalOn']);
    _contacts = data.contacts || {};
    _globalOn = data.globalOn !== false;

    if (!data.ageRecipient || !data.ageEncryptedIdentity) {
      const hasDraft = await restoreImportDraft();
      show(hasDraft ? 'import' : 'setup');
      return;
    }

    const identity = await getSessionIdentity();
    if (identity) {
      _sessionIdentity = identity;
      // background.js already holds the identity (it persisted it to session
      // storage on the original unlock).  Re-signal Discord tabs in case any
      // opened since then — background will handle retry logic on its own for
      // tab-reload events; this covers tabs that were already open when the
      // popup re-opens.
      sendToDiscordTabs({ type: 'UNLOCK' });
      await showMain();
    } else {
      document.getElementById('btn-goto-setup').hidden = false;
      show('lock');
    }
  }

  // ─── Lock screen ─────────────────────────────────────────────────────────────

  document.getElementById('btn-unlock').addEventListener('click', doUnlock);
  document.getElementById('passphrase-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') doUnlock();
  });

  document.getElementById('btn-goto-setup').addEventListener('click', () => {
    document.getElementById('reset-confirm-input').value  = '';
    document.getElementById('btn-reset-confirm').disabled = true;
    document.getElementById('modal-reset-keypair').hidden = false;
  });
  document.getElementById('btn-reset-cancel').addEventListener('click', () => {
    document.getElementById('reset-confirm-input').value  = '';
    document.getElementById('modal-reset-keypair').hidden = true;
  });
  document.getElementById('reset-confirm-input').addEventListener('input', e => {
    document.getElementById('btn-reset-confirm').disabled = (e.target.value !== 'CONFIRM');
  });
  document.getElementById('btn-reset-confirm').addEventListener('click', async () => {
    document.getElementById('modal-reset-keypair').hidden = true;
    await store.remove(['ageRecipient', 'ageEncryptedIdentity', 'contacts', 'globalOn']);
    await clearIdentityInBackground();
    _contacts = {};
    _globalOn = true;
    sendToDiscordTabs({ type: 'RELOCK' });
    document.getElementById('btn-goto-setup').hidden = true;
    document.getElementById('passphrase-input').value = '';
    document.getElementById('unlock-error').hidden = true;
    show('setup');
  });

  async function doUnlock() {
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase) return;

    const errEl = document.getElementById('unlock-error');
    const btn   = document.getElementById('btn-unlock');
    errEl.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Unlocking…';

    try {
      const { ageEncryptedIdentity } = await store.get(['ageEncryptedIdentity']);
      if (!ageEncryptedIdentity) throw new Error('No keypair found.');

      const d = new age.Decrypter();
      d.addPassphrase(passphrase);
      const identityBytes = await d.decrypt(base64ToBytes(ageEncryptedIdentity), 'uint8array');
      const identity      = new TextDecoder().decode(identityBytes);

      const identityLines = identity.split('\n');
      if (!identityLines[0].startsWith('AGE-SECRET-KEY-1'))
        throw new Error('Decrypted data is not a valid age identity.');
      if (!identityLines[1]?.startsWith('ed25519priv:'))
        throw new Error('Keypair missing Ed25519 signing key — please reset and generate a new keypair.');

      await setIdentityInBackground(identity);
      _sessionIdentity = identity;
      document.getElementById('passphrase-input').value = '';
      await showMain();

    } catch (e) {
      const msg = e.message?.toLowerCase() ?? '';
      showErr(
        errEl,
        (msg.includes('bad') || msg.includes('decrypt') || msg.includes('passphrase') || msg.includes('hmac'))
          ? 'Wrong passphrase. Try again.'
          : 'Unlock failed: ' + e.message
      );
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  }

  // ─── Setup / keygen ──────────────────────────────────────────────────────────

  const setupPassEl = document.getElementById('setup-passphrase');
  const strengthBar = document.getElementById('strength-bar');
  const strengthLbl = document.getElementById('strength-label');

  setupPassEl.addEventListener('input', () => {
    const p = setupPassEl.value;
    let score = 0;
    if (p.length >= 20) score++;
    if (p.length >= 30) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[a-z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    const colors = ['#ed4245','#ed4245','#fee75c','#fee75c','#57f287','#57f287','#57f287'];
    strengthBar.style.width      = Math.round((score / 6) * 100) + '%';
    strengthBar.style.background = colors[score];
    strengthLbl.style.color      = colors[score];
    strengthLbl.textContent      = p.length ? ['Too short','Weak','Weak','Fair','Good','Strong','Very strong'][score] : '';
  });

  function validatePassphrase(p) {
    const errs = [];
    if (p.length < 20)           errs.push('at least 20 characters');
    if (!/[A-Z]/.test(p))        errs.push('an uppercase letter (A–Z)');
    if (!/[a-z]/.test(p))        errs.push('a lowercase letter (a–z)');
    if (!/[0-9]/.test(p))        errs.push('a number (0–9)');
    if (!/[^A-Za-z0-9]/.test(p)) errs.push('a special character (e.g. ! & *)');
    return errs.length ? 'Passphrase must include: ' + errs.join(', ') + '.' : null;
  }

  document.getElementById('btn-generate').addEventListener('click', async () => {
    const pass  = setupPassEl.value;
    const pass2 = document.getElementById('setup-passphrase2').value;
    const errEl = document.getElementById('setup-error');
    errEl.hidden = true;

    const passErr = validatePassphrase(pass);
    if (passErr)        { showErr(errEl, passErr); return; }
    if (pass !== pass2) { showErr(errEl, 'Passphrases do not match.'); return; }

    document.getElementById('btn-generate').hidden  = true;
    document.getElementById('setup-spinner').hidden = false;

    try {
      const identity  = await age.generateIdentity();
      const recipient = await age.identityToRecipient(identity);

      const sigPair    = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const sigPrivRaw = await crypto.subtle.exportKey('pkcs8', sigPair.privateKey);
      const sigPubRaw  = await crypto.subtle.exportKey('raw',   sigPair.publicKey);
      const sigPrivB64 = bytesToBase64Url(new Uint8Array(sigPrivRaw));
      const sigPubB64  = bytesToBase64Url(new Uint8Array(sigPubRaw));

      const identityBlob = identity + '\ned25519priv:' + sigPrivB64;

      const fullRecipient = recipient + ';ed25519:' + sigPubB64;

      // scrypt N=18: the age default. Key generation runs in the popup page, not
      // the service worker, so the UI can show a spinner without freezing.
      const enc = new age.Encrypter();
      enc.setPassphrase(pass);
      enc.setScryptWorkFactor(18);
      const encryptedB64 = bytesToBase64(await enc.encrypt(new TextEncoder().encode(identityBlob)));

      await store.set({ ageRecipient: fullRecipient, ageEncryptedIdentity: encryptedB64, contacts: {}, globalOn: true });
      await setIdentityInBackground(identityBlob);
      _sessionIdentity = identityBlob;
      _contacts = {};
      _globalOn = true;
      await showMain();

    } catch (e) {
      showErr(document.getElementById('setup-error'), 'Key generation failed: ' + e.message);
    } finally {
      document.getElementById('btn-generate').hidden  = false;
      document.getElementById('setup-spinner').hidden = true;
    }
  });

  // ─── Import existing keypair ────────────────────────────────────────────────

  const DRAFT_TTL           = 10 * 60 * 1000;
  // Intentionally excludes passphrase fields — passphrases must never be
  // persisted, even to session storage.
  const IMPORT_DRAFT_FIELDS = ['import-blob'];

  async function saveImportDraft() {
    const draft = { ts: Date.now() };
    IMPORT_DRAFT_FIELDS.forEach(id => { draft[id] = document.getElementById(id).value; });
    try {
      if (chrome.storage.session)
        await new Promise(r => chrome.storage.session.set({ import_draft: draft }, r));
    } catch {}
  }

  async function restoreImportDraft() {
    try {
      if (!chrome.storage.session) return false;
      const { import_draft: draft } =
        await new Promise(res => chrome.storage.session.get('import_draft', res));
      if (!draft || Date.now() - draft.ts > DRAFT_TTL) return false;
      IMPORT_DRAFT_FIELDS.forEach(id => { if (draft[id]) document.getElementById(id).value = draft[id]; });
      return IMPORT_DRAFT_FIELDS.some(id => document.getElementById(id).value.trim());
    } catch { return false; }
  }

  async function clearImportDraft() {
    try {
      if (chrome.storage.session)
        await new Promise(r => chrome.storage.session.remove('import_draft', r));
    } catch {}
  }

  IMPORT_DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveImportDraft));
  document.getElementById('btn-show-import').addEventListener('click', () => show('import'));
  document.getElementById('btn-back-import').addEventListener('click', () => show('setup'));

  document.getElementById('btn-import').addEventListener('click', async () => {
    const blob  = document.getElementById('import-blob').value.trim();
    const pass  = document.getElementById('import-passphrase').value;
    const pass2 = document.getElementById('import-passphrase2').value;
    const errEl = document.getElementById('import-error');
    errEl.hidden = true;

    const passErr = validatePassphrase(pass);
    if (passErr)        { showErr(errEl, passErr); return; }
    if (pass !== pass2) { showErr(errEl, 'Passphrases do not match.'); return; }
    if (!blob)          { showErr(errEl, 'Paste your private key blob first.'); return; }

    const lines = blob.split('\n');
    if (!lines[0].startsWith('AGE-SECRET-KEY-1')) {
      showErr(errEl, 'Invalid blob — line 1 must be an age secret key (AGE-SECRET-KEY-1…).');
      return;
    }
    if (!lines[1]?.startsWith('ed25519priv:')) {
      showErr(errEl, 'Invalid blob — line 2 must be an Ed25519 private key (ed25519priv:…).');
      return;
    }

    const btn = document.getElementById('btn-import');
    btn.hidden = true;
    document.getElementById('import-spinner').hidden = false;

    try {
      const identity  = lines[0];
      const recipient = await age.identityToRecipient(identity);

      const sigPrivBytes = base64UrlToBytes(lines[1].slice('ed25519priv:'.length));
      const sigPrivKey   = await crypto.subtle.importKey(
        'pkcs8', sigPrivBytes, { name: 'Ed25519' }, true, ['sign']
      );
      // Web Crypto has no Ed25519 privkey→pubkey derivation; use JWK round-trip.
      const jwk       = await crypto.subtle.exportKey('jwk', sigPrivKey);
      const pubJwk    = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, key_ops: ['verify'] };
      const sigPubKey = await crypto.subtle.importKey('jwk', pubJwk, { name: 'Ed25519' }, true, ['verify']);
      const sigPubRaw = await crypto.subtle.exportKey('raw', sigPubKey);
      const sigPubB64 = bytesToBase64Url(new Uint8Array(sigPubRaw));

      const fullRecipient = recipient + ';ed25519:' + sigPubB64;
      const identityBlob  = blob;

      const enc = new age.Encrypter();
      enc.setPassphrase(pass);
      enc.setScryptWorkFactor(18);
      const encryptedB64 = bytesToBase64(await enc.encrypt(new TextEncoder().encode(identityBlob)));

      await store.set({ ageRecipient: fullRecipient, ageEncryptedIdentity: encryptedB64, contacts: {}, globalOn: true });
      await setIdentityInBackground(identityBlob);
      _sessionIdentity = identityBlob;
      _contacts = {};
      _globalOn = true;

      document.getElementById('import-blob').value        = '';
      document.getElementById('import-passphrase').value  = '';
      document.getElementById('import-passphrase2').value = '';
      clearImportDraft();
      await showMain();

    } catch (e) {
      showErr(errEl, 'Import failed: ' + e.message);
    } finally {
      btn.hidden = false;
      document.getElementById('import-spinner').hidden = true;
    }
  });

  // ─── Main screen ─────────────────────────────────────────────────────────────

  async function showMain() {
    // Navigate immediately so back buttons feel instant — don't wait for storage.
    // We render with the current in-memory state first, then refresh from storage
    // in case another context changed contacts or globalOn since last load.
    document.getElementById('global-toggle').checked = _globalOn;
    renderContacts();
    show('main');
    // Background refresh — updates the list if storage differs from memory.
    const data = await store.get(['contacts', 'globalOn']);
    _contacts = data.contacts || {};
    _globalOn = data.globalOn !== false;
    document.getElementById('global-toggle').checked = _globalOn;
    renderContacts();
  }

  document.getElementById('global-toggle').addEventListener('change', async (e) => {
    _globalOn = e.target.checked;
    await store.set({ globalOn: _globalOn });
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
  });

  document.getElementById('btn-lock').addEventListener('click', async () => {
    await clearIdentityInBackground();
    _sessionIdentity = null;
    sendToDiscordTabs({ type: 'RELOCK' });
    document.getElementById('passphrase-input').value = '';
    document.getElementById('unlock-error').hidden = true;
    document.getElementById('btn-goto-setup').hidden = true;
    show('lock');
  });

  document.getElementById('btn-my-key').addEventListener('click', showMyKey);
  document.getElementById('btn-about').addEventListener('click', showAbout);

  // ─── Contacts ────────────────────────────────────────────────────────────────

  function renderContacts() {
    const list  = document.getElementById('contacts-list');
    const empty = document.getElementById('no-contacts');
    list.querySelectorAll('.contact-card').forEach(el => el.remove());
    const ids = Object.keys(_contacts);
    empty.hidden = ids.length > 0;
    ids.forEach(id => {
      const c    = _contacts[id];
      const card = document.createElement('div');
      card.className = 'contact-card';

      const avatar = Object.assign(document.createElement('div'), {
        className:   'contact-avatar',
        textContent: (c.username?.[0] ?? '?').toUpperCase(),
      });
      const name = Object.assign(document.createElement('div'), {
        className:   'contact-name',
        textContent: c.username,
      });
      const chip = Object.assign(document.createElement('span'), {
        className:   `contact-chip ${c.enabled ? 'chip-on' : 'chip-off'}`,
        textContent: c.enabled ? '🔒 Encrypted' : '🔓 Disabled',
      });
      const info = document.createElement('div');
      info.className = 'contact-info';
      info.append(name, chip);
      card.append(avatar, info);
      card.addEventListener('click', () => openContactSheet(id));
      list.appendChild(card);
    });
  }

  // ─── Add contact ─────────────────────────────────────────────────────────────

  const DRAFT_FIELDS = ['contact-channel-id', 'contact-username', 'contact-key'];

  async function saveDraft() {
    const draft = { ts: Date.now() };
    DRAFT_FIELDS.forEach(id => { draft[id] = document.getElementById(id).value; });
    try {
      if (chrome.storage.session)
        await new Promise(r => chrome.storage.session.set({ add_contact_draft: draft }, r));
    } catch {}
  }

  async function restoreDraft() {
    try {
      if (!chrome.storage.session) return false;
      const { add_contact_draft: draft } =
        await new Promise(res => chrome.storage.session.get('add_contact_draft', res));
      if (!draft || Date.now() - draft.ts > DRAFT_TTL) return false;
      DRAFT_FIELDS.forEach(id => { if (draft[id]) document.getElementById(id).value = draft[id]; });
      return DRAFT_FIELDS.some(id => draft[id]?.trim());
    } catch { return false; }
  }

  async function clearDraft() {
    try {
      if (chrome.storage.session)
        await new Promise(r => chrome.storage.session.remove('add_contact_draft', r));
    } catch {}
  }

  DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveDraft));

  async function inferChannelId() {
    return new Promise(resolve => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const m = (tabs[0]?.url ?? '').match(/discord\.com\/channels\/@me\/(\d+)/);
        resolve(m ? m[1] : null);
      });
    });
  }

  document.getElementById('btn-add-contact').addEventListener('click', async () => {
    const hasDraft = await restoreDraft();
    if (!hasDraft) {
      const channelId = await inferChannelId();
      if (channelId) document.getElementById('contact-channel-id').value = channelId;
    }
    show('add-contact');
  });

  document.getElementById('btn-back-add').addEventListener('click', async () => {
    await clearDraft();
    DRAFT_FIELDS.forEach(id => { document.getElementById(id).value = ''; });
    showMain();
  });

  document.getElementById('btn-save-contact').addEventListener('click', async () => {
    const channelId = document.getElementById('contact-channel-id').value.trim();
    const username  = document.getElementById('contact-username').value.trim();
    const recipient = document.getElementById('contact-key').value.trim();
    const errEl     = document.getElementById('add-contact-error');
    errEl.hidden    = true;

    if (!channelId || !username || !recipient) { showErr(errEl, 'All fields are required.'); return; }
    if (!/^\d+$/.test(channelId)) { showErr(errEl, 'Channel ID must be numeric.'); return; }
    if (!recipient.startsWith('age1')) { showErr(errEl, 'Public key must start with "age1…".'); return; }
    if (recipient.startsWith('AGE-SECRET-KEY-')) { showErr(errEl, 'That is a private key — paste their public key (age1…) instead.'); return; }
    if (recipient.length < 10) { showErr(errEl, 'Key seems too short. Make sure you copied it in full.'); return; }

    try {
      const test = new age.Encrypter();
      test.addRecipient(recipient.split(';')[0]);
      await test.encrypt(new TextEncoder().encode(''));
    } catch (e) {
      showErr(errEl, 'Key validation failed: ' + e.message);
      return;
    }

    _contacts[channelId] = { username, ageRecipient: recipient, enabled: true };
    await store.set({ contacts: _contacts });
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
    DRAFT_FIELDS.forEach(id => { document.getElementById(id).value = ''; });
    await clearDraft();
    await showMain();
  });

  // ─── Contact sheet ───────────────────────────────────────────────────────────

  async function openContactSheet(id) {
    _selectedId = id;
    const c   = _contacts[id];
    const fpEl = document.getElementById('sheet-contact-fp');
    document.getElementById('sheet-contact-name').textContent = c.username;
    document.getElementById('sheet-contact-toggle').checked   = c.enabled;
    fpEl.textContent = 'Computing…';
    document.getElementById('sheet-contact').hidden  = false;
    document.getElementById('sheet-backdrop').hidden = false;
    fpEl.textContent = await keyFingerprint(c.ageRecipient);
  }

  function closeSheet() {
    document.getElementById('sheet-contact').hidden  = true;
    document.getElementById('sheet-backdrop').hidden = true;
    _selectedId = null;
  }

  document.getElementById('btn-close-sheet').addEventListener('click', closeSheet);
  document.getElementById('sheet-backdrop').addEventListener('click', closeSheet);

  document.getElementById('sheet-contact-toggle').addEventListener('change', async (e) => {
    if (!_selectedId) return;
    _contacts[_selectedId].enabled = e.target.checked;
    await store.set({ contacts: _contacts });
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
    renderContacts();
  });

  document.getElementById('btn-delete-contact').addEventListener('click', () => {
    if (!_selectedId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedId].username}" and their public key will be permanently removed.`;
    document.getElementById('modal-delete-contact').hidden = false;
  });

  document.getElementById('btn-delete-cancel').addEventListener('click', () => {
    document.getElementById('modal-delete-contact').hidden = true;
  });

  document.getElementById('btn-delete-confirm').addEventListener('click', async () => {
    document.getElementById('modal-delete-contact').hidden = true;
    if (!_selectedId) return;
    delete _contacts[_selectedId];
    await store.set({ contacts: _contacts });
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
    closeSheet();
    renderContacts();
  });

  document.getElementById('btn-edit-contact').addEventListener('click', () => {
    if (!_selectedId) return;
    const c = _contacts[_selectedId];
    document.getElementById('edit-channel-id').value = _selectedId;
    document.getElementById('edit-username').value   = c.username;
    document.getElementById('edit-key').value        = c.ageRecipient;
    document.getElementById('edit-contact-error').hidden = true;
    closeSheet();
    show('edit-contact');
  });

  document.getElementById('btn-back-edit').addEventListener('click', showMain);

  document.getElementById('btn-save-edit').addEventListener('click', async () => {
    const channelId = document.getElementById('edit-channel-id').value.trim();
    const username  = document.getElementById('edit-username').value.trim();
    const recipient = document.getElementById('edit-key').value.trim();
    const errEl     = document.getElementById('edit-contact-error');
    errEl.hidden    = true;

    if (!channelId || !username || !recipient) { showErr(errEl, 'All fields are required.'); return; }
    if (!/^\d+$/.test(channelId))              { showErr(errEl, 'Channel ID must be numeric.'); return; }
    if (!recipient.startsWith('age1'))          { showErr(errEl, 'Public key must start with "age1…".'); return; }
    if (recipient.startsWith('AGE-SECRET-KEY-')) { showErr(errEl, 'That is a private key — paste their public key (age1…) instead.'); return; }
    if (recipient.length < 10)                  { showErr(errEl, 'Key seems too short. Make sure you copied it in full.'); return; }

    try {
      const test = new age.Encrypter();
      test.addRecipient(recipient.split(';')[0]);
      await test.encrypt(new TextEncoder().encode(''));
    } catch (e) {
      showErr(errEl, 'Key validation failed: ' + e.message);
      return;
    }

    if (_selectedId && _selectedId !== channelId) delete _contacts[_selectedId];
    _contacts[channelId] = { username, ageRecipient: recipient, enabled: _contacts[channelId]?.enabled ?? true };
    _selectedId = null;
    await store.set({ contacts: _contacts });
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
    await showMain();
  });

  // ─── Export contacts ─────────────────────────────────────────────────────

  document.getElementById('btn-export-contacts').addEventListener('click', () => {
    const entries = Object.entries(_contacts).map(([channelId, c]) => ({
      channelId,
      username:     c.username,
      ageRecipient: c.ageRecipient,
      enabled:      c.enabled,
    }));

    const json = JSON.stringify({ version: 1, contacts: entries }, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);

    const datePart = new Date()
      .toLocaleDateString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit' })
      .replace(/[\/\\:]/g, '-');

    const a = Object.assign(document.createElement('a'), {
      href:     url,
      download: `discord-age-contacts-${datePart}.json`,
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  // ─── Import contacts ──────────────────────────────────────────────────────
  // Both Chrome and Firefox block file picking from an extension popup:
  //   Chrome  — showOpenFilePicker() throws NotAllowedError (popup is not a
  //              top-level browsing context); <input type="file"> steals focus
  //              and closes the popup.
  //   Firefox — <input type="file"> closes the popup (unfixed bug 1292701);
  //              showOpenFilePicker() has the same focus problem.
  //
  // Universal fix: open a full-page import helper tab. It writes the chosen
  // JSON to chrome.storage.session, then calls chrome.action.openPopup()
  // (Chrome ≥ 127) or closes itself (Firefox — user clicks the icon again).
  // On the next popup boot, checkPendingImport() picks up the stored JSON.

  async function doImportContacts(json) {
    const msgEl = document.getElementById('modal-import-contacts-msg');
    const modal  = document.getElementById('modal-import-contacts');

    let parsed;
    try { parsed = JSON.parse(json); }
    catch {
      msgEl.textContent = 'Could not parse file — make sure it is a valid contacts export.';
      modal.hidden = false;
      return;
    }

    const entries = Array.isArray(parsed) ? parsed : parsed?.contacts;
    if (!Array.isArray(entries)) {
      msgEl.textContent = 'Unrecognised format — expected a contacts export JSON.';
      modal.hidden = false;
      return;
    }

    let added = 0, updated = 0, skipped = 0;
    for (const entry of entries) {
      const { channelId, username, ageRecipient, enabled } = entry ?? {};
      if (!channelId || !username || !ageRecipient) { skipped++; continue; }
      if (!/^\d+$/.test(channelId))                 { skipped++; continue; }
      if (!ageRecipient.startsWith('age1'))          { skipped++; continue; }
      if (typeof username !== 'string' || username.length > 64) { skipped++; continue; }

      // Validate key format the same way the manual add-contact flow does.
      try {
        const test = new age.Encrypter();
        test.addRecipient(ageRecipient.split(';')[0]);
        await test.encrypt(new TextEncoder().encode(''));
      } catch { skipped++; continue; }

      const exists = Object.prototype.hasOwnProperty.call(_contacts, channelId);
      _contacts[channelId] = { username, ageRecipient, enabled: (enabled !== false) };
      exists ? updated++ : added++;
    }

    await store.set({ contacts: _contacts });
    // CONTACTS_UPDATED tells content scripts to reload contacts from storage.
    // No need to re-send UNLOCK — the background already holds the identity
    // and content scripts are already unlocked.
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
    renderContacts();

    const parts = [];
    if (added)   parts.push(`${added} contact${added   !== 1 ? 's' : ''} added`);
    if (updated) parts.push(`${updated} contact${updated !== 1 ? 's' : ''} updated`);
    if (skipped) parts.push(`${skipped} skipped (invalid)`);
    msgEl.textContent = 'Import complete — ' + (parts.join(', ') || 'nothing changed') + '.';
    modal.hidden = false;
  }

  document.getElementById('btn-import-contacts').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup/import-helper.html') });
  });

  // Tab ID of the import helper page, set when a pending import is detected.
  // Used to close the helper tab when the user dismisses the result modal
  // (OK button) or when the popup is closed while the modal is still open.
  let _importHelperTabId = null;

  function closeImportHelperTab() {
    if (_importHelperTabId === null) return;
    const id = _importHelperTabId;
    _importHelperTabId = null;
    chrome.tabs.remove(id, () => void chrome.runtime.lastError);
  }

  // On boot, check whether the import helper wrote JSON to session storage.
  async function checkPendingImport() {
    try {
      if (!chrome.storage.session) return;
      const data = await new Promise(r =>
        chrome.storage.session.get(['pending_import', 'pending_import_tab'], r));
      if (!data.pending_import) return;
      // Guard against oversized payloads that could exhaust session storage quota
      // or cause a DoS on the import loop.
      if (data.pending_import.length > 500_000) {
        await new Promise(r => chrome.storage.session.remove(
          ['pending_import', 'pending_import_tab'], r));
        const msgEl = document.getElementById('modal-import-contacts-msg');
        msgEl.textContent = 'Import failed — file too large (max 500 KB).';
        document.getElementById('modal-import-contacts').hidden = false;
        return;
      }
      _importHelperTabId = data.pending_import_tab ?? null;
      await new Promise(r => chrome.storage.session.remove(
        ['pending_import', 'pending_import_tab'], r));
      await doImportContacts(data.pending_import);
    } catch {}
  }

  document.getElementById('btn-import-contacts-ok').addEventListener('click', () => {
    document.getElementById('modal-import-contacts').hidden = true;
    closeImportHelperTab();
  });

  // Also close the helper tab if the popup is closed while the modal is visible
  // (user clicks away / presses Escape). window.unload fires when the popup closes.
  window.addEventListener('unload', () => {
    if (!document.getElementById('modal-import-contacts').hidden) {
      closeImportHelperTab();
    }
  });

  // ─── My key screen ───────────────────────────────────────────────────────

  document.getElementById('btn-back-key').addEventListener('click', () => {
    _myKeyGeneration++; // abort any in-flight showMyKey async continuations
    showMain();
  });

  async function showMyKey() {
    const gen = ++_myKeyGeneration;
    const { ageRecipient } = await store.get(['ageRecipient']);
    // If the back button was clicked while we were awaiting, abort.
    if (gen !== _myKeyGeneration) return;
    if (!ageRecipient) return;
    document.getElementById('my-key-box').textContent = ageRecipient;
    document.getElementById('my-key-fp').textContent = 'Computing fingerprint…';
    show('my-key');
    const fp = await keyFingerprint(ageRecipient);
    // Guard the second continuation too — back button may have been clicked
    // after show('my-key') but before keyFingerprint resolved.
    if (gen === _myKeyGeneration)
      document.getElementById('my-key-fp').textContent = fp;
  }

  document.getElementById('btn-copy-key').addEventListener('click', async () => {
    const { ageRecipient } = await store.get(['ageRecipient']);
    if (!ageRecipient) return;
    try {
      await navigator.clipboard.writeText(ageRecipient);
    } catch {
      const ta = Object.assign(document.createElement('textarea'), { value: ageRecipient });
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    const btn = document.getElementById('btn-copy-key');
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1800);
  });

  // ─── Export private key ──────────────────────────────────────────────────────

  document.getElementById('btn-export-key').addEventListener('click', () => {
    document.getElementById('export-passphrase-input').value = '';
    document.getElementById('export-passphrase-error').hidden = true;
    document.getElementById('modal-export-key').hidden = false;
  });
  document.getElementById('btn-export-cancel').addEventListener('click', () => {
    document.getElementById('export-passphrase-input').value = '';
    document.getElementById('modal-export-key').hidden = true;
  });
  document.getElementById('export-passphrase-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btn-export-confirm').click();
  });
  document.getElementById('btn-export-confirm').addEventListener('click', async () => {
    const passphrase = document.getElementById('export-passphrase-input').value;
    const errEl      = document.getElementById('export-passphrase-error');
    const btn        = document.getElementById('btn-export-confirm');
    errEl.hidden     = true;
    if (!passphrase) { showErr(errEl, 'Enter your passphrase.'); return; }

    btn.disabled = true;
    btn.textContent = 'Verifying…';
    try {
      const { ageEncryptedIdentity } = await store.get(['ageEncryptedIdentity']);
      const d = new age.Decrypter();
      d.addPassphrase(passphrase);
      const identityBytes = await d.decrypt(base64ToBytes(ageEncryptedIdentity), 'uint8array');
      const identity      = new TextDecoder().decode(identityBytes);

      document.getElementById('export-passphrase-input').value = '';
      document.getElementById('modal-export-key').hidden = true;
      document.getElementById('export-key-blob').value = identity;
      document.getElementById('modal-export-display').hidden = false;
    } catch (e) {
      const msg = e.message?.toLowerCase() ?? '';
      showErr(errEl,
        (msg.includes('bad') || msg.includes('decrypt') || msg.includes('passphrase') || msg.includes('hmac'))
          ? 'Wrong passphrase.'
          : 'Verification failed: ' + e.message
      );
    } finally {
      btn.disabled = false;
      btn.textContent = 'Reveal key';
    }
  });
  function closeExportDisplay() {
    document.getElementById('export-key-blob').value = '';
    document.getElementById('modal-export-display').hidden = true;
  }
  document.getElementById('btn-export-copy').addEventListener('click', async () => {
    const blob = document.getElementById('export-key-blob').value;
    try { await navigator.clipboard.writeText(blob); } catch { }
    closeExportDisplay();
  });
  document.getElementById('btn-export-close').addEventListener('click', closeExportDisplay);

  // ─── Keypair regeneration ────────────────────────────────────────────────────

  document.getElementById('btn-regen').addEventListener('click', () => {
    document.getElementById('regen-confirm-input').value   = '';
    document.getElementById('btn-regen-confirm').disabled  = true;
    document.getElementById('modal-regen').hidden          = false;
  });
  document.getElementById('btn-regen-cancel').addEventListener('click', () => {
    document.getElementById('modal-regen').hidden = true;
  });
  document.getElementById('regen-confirm-input').addEventListener('input', e => {
    document.getElementById('btn-regen-confirm').disabled = (e.target.value !== 'CONFIRM');
  });
  document.getElementById('btn-regen-confirm').addEventListener('click', async () => {
    document.getElementById('modal-regen').hidden = true;
    Object.keys(_contacts).forEach(id => { _contacts[id].enabled = false; });
    await store.remove(['ageRecipient', 'ageEncryptedIdentity']);
    await store.set({ contacts: _contacts });
    await clearIdentityInBackground();
    _sessionIdentity = null;
    sendToDiscordTabs({ type: 'RELOCK' });
    document.getElementById('setup-passphrase').value  = '';
    document.getElementById('setup-passphrase2').value = '';
    document.getElementById('setup-error').hidden      = true;
    show('setup');
  });

  // ─── Utilities ───────────────────────────────────────────────────────────────

  function showErr(el, msg) { el.textContent = msg; el.hidden = false; }

  // BLAKE3 (64-byte output) fingerprint. Verify: printf '%s' "age1..." | b3sum --length 64
  async function keyFingerprint(recipient) {
    if (!recipient) return '(no key)';
    try {
      const bytes = nobleHashes.blake3(new TextEncoder().encode(recipient), { dkLen: 64 });
      const hex   = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      return hex.match(/.{1,4}/g).reduce((lines, chunk, i) => {
        if (i % 8 === 0) lines.push('');
        lines[lines.length - 1] += (lines[lines.length - 1] ? ' ' : '') + chunk;
        return lines;
      }, []).join('\n');
    } catch {
      if (recipient.length <= 28) return recipient;
      return recipient.slice(0, 16) + '…' + recipient.slice(-12);
    }
  }

  function bytesToBase64(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64UrlToBytes(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function base64ToBytes(b64) {
    const bin  = atob(b64);
    const out  = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ─── About screen ────────────────────────────────────────────────────────────

  document.getElementById('btn-back-about').addEventListener('click', showMain);

  const _aboutLinks = {
    'about-repo-link':    'https://github.com/SenseiDeElite/discord-age-encryption',
    'about-typage-link':  'https://github.com/FiloSottile/typage/blob/main/LICENSE',
    'about-noble-link':   'https://github.com/paulmillr/noble-hashes/blob/main/LICENSE',
    'about-license-link': 'https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE',
  };
  Object.entries(_aboutLinks).forEach(([id, url]) => {
    document.getElementById(id).addEventListener('click', () => {
      chrome.tabs.create({ url });
    });
  });

  function showAbout() {
    const ver = chrome.runtime.getManifest?.()?.version ?? '';
    document.getElementById('about-version').textContent = ver ? 'v' + ver : '';
    show('about');
  }

  // ─── Boot ────────────────────────────────────────────────────────────────────

  async function bootWithDraftCheck() {
    await boot();
    if (!document.getElementById('screen-main').hidden) {
      if (await restoreDraft()) show('add-contact');
      else await checkPendingImport();
    }
  }

  bootWithDraftCheck().catch(e => console.error('[age] popup boot error:', e));

})();
