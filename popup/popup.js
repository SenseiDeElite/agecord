// popup.js — Discord Age Encryption
//
// Key storage : age identity encrypted with user passphrase (scrypt N=2^18),
//               stored as base64 in chrome.storage.local.
// Session     : decrypted identity kept in chrome.storage.session;
//               background service worker holds it in memory and sends only the
//               non-extractable Ed25519 signing CryptoKey to content scripts.
// Scrypt      : offloaded to popup/scrypt-worker.js so the UI stays responsive.

(() => {
  'use strict';

  // ─── Constants ───────────────────────────────────────────────────────────────

  const MAX_CONTACTS    = 1000;
  const MAX_CHANNEL_ID  = 20;   // chars
  const MIN_CHANNEL_ID  = 1;
  const MAX_USERNAME    = 32;
  const MIN_USERNAME    = 1;
  const MAX_IMPORT_ROWS = 1000;

  // ─── Storage helpers ────────────────────────────────────────────────────────
  const store = {
    get:    keys => new Promise(r => chrome.storage.local.get(keys, r)),
    set:    data => new Promise(r => chrome.storage.local.set(data, r)),
    remove: keys => new Promise(r => chrome.storage.local.remove(keys, r)),
  };

  // ─── Background messaging ────────────────────────────────────────────────────
  // All tab-relay operations go through the background service worker.

  function bgSend(msg) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage(msg, r => {
        void chrome.runtime.lastError;
        resolve(r);
      });
    });
  }

  // ─── State ──────────────────────────────────────────────────────────────────
  let _contacts        = {};
  let _globalOn        = true;
  let _selectedId      = null;
  let _editingId       = null;   // channelId currently open in the edit screen
  let _sessionIdentity = null;  // decrypted two-line identity blob, kept for export
  // ─── Screen router ──────────────────────────────────────────────────────────
  const screens = ['lock', 'setup', 'import', 'main', 'add-contact', 'edit-contact', 'my-key', 'about'];
  const show = screenId =>
    screens.forEach(id => { document.getElementById(`screen-${id}`).hidden = (id !== screenId); });

  // ─── Session helpers ─────────────────────────────────────────────────────────

  async function getSessionIdentity() {
    try {
      if (chrome.storage.session) {
        const r = await new Promise(res => chrome.storage.session.get(['age_unlocked', 'age_identity'], res));
        return r.age_unlocked === true ? (r.age_identity ?? null) : null;
      }
    } catch {}
    return null;
  }

  async function setSession(identity) {
    try {
      if (chrome.storage.session)
        await new Promise(res => chrome.storage.session.set({ age_unlocked: true, age_identity: identity }, res));
    } catch {}
  }

  async function clearSession() {
    try {
      if (chrome.storage.session)
        await new Promise(res => chrome.storage.session.remove(['age_unlocked', 'age_identity'], res));
    } catch {}
  }

  // ─── Scrypt worker ───────────────────────────────────────────────────────────
  // Spawns a fresh dedicated worker per call, terminated on completion.
  // The worker runs age scrypt at N=2^18 off the UI thread.

  function runScryptWorker(msg) {
    return new Promise((resolve, reject) => {
      const workerUrl = chrome.runtime.getURL('popup/scrypt-worker.js');
      let worker;
      try {
        worker = new Worker(workerUrl);
      } catch (e) {
        reject(new Error('Could not start scrypt worker: ' + e.message));
        return;
      }
      worker.onmessage = ({ data }) => {
        worker.terminate();
        if (data.ok) resolve(data);
        else reject(new Error(data.error ?? 'Worker error'));
      };
      worker.onerror = (e) => {
        worker.terminate();
        reject(new Error(e.message ?? 'Worker crashed'));
      };
      worker.postMessage(msg);
    });
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
      // Tell background — it will import the signing key and relay to tabs.
      await bgSend({ type: 'UNLOCK', identity });
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
    await clearSession();
    _contacts = {};
    _globalOn = true;
    await bgSend({ type: 'RELOCK' });
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

      const result = await runScryptWorker({ op: 'DECRYPT', encryptedB64: ageEncryptedIdentity, passphrase });
      const identity = result.identity;

      const identityLines = identity.split('\n');
      if (!identityLines[0].startsWith('AGE-SECRET-KEY-1'))
        throw new Error('Decrypted data is not a valid age identity.');
      if (!identityLines[1]?.startsWith('ed25519priv:'))
        throw new Error('Keypair missing Ed25519 signing key — please reset and generate a new keypair.');

      await setSession(identity);
      _sessionIdentity = identity;
      await bgSend({ type: 'UNLOCK', identity });
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

      const identityBlob  = identity + '\ned25519priv:' + sigPrivB64;
      const fullRecipient = recipient + ';ed25519:' + sigPubB64;

      // Encrypt with N=2^18 in the worker.
      const result = await runScryptWorker({ op: 'ENCRYPT', identityBlob, passphrase: pass });

      await store.set({ ageRecipient: fullRecipient, ageEncryptedIdentity: result.encryptedB64, contacts: {}, globalOn: true });
      await setSession(identityBlob);
      _sessionIdentity = identityBlob;
      _contacts = {};
      _globalOn = true;

      await bgSend({ type: 'UNLOCK', identity: identityBlob });
      await bgSend({ type: 'RELOAD_DISCORD_TABS' });
      await showMain();

    } catch (e) {
      showErr(document.getElementById('setup-error'), 'Key generation failed: ' + e.message);
    } finally {
      document.getElementById('btn-generate').hidden  = false;
      document.getElementById('setup-spinner').hidden = true;
    }
  });

  // ─── Import existing keypair ─────────────────────────────────────────────────

  const DRAFT_TTL           = 10 * 60 * 1000;
  const IMPORT_DRAFT_FIELDS = ['import-passphrase', 'import-passphrase2'];
  // NOTE: 'import-blob' is intentionally excluded — private key material must
  // never be persisted to session storage, even temporarily.

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
      const jwk       = await crypto.subtle.exportKey('jwk', sigPrivKey);
      const pubJwk    = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, key_ops: ['verify'] };
      const sigPubKey = await crypto.subtle.importKey('jwk', pubJwk, { name: 'Ed25519' }, true, ['verify']);
      const sigPubRaw = await crypto.subtle.exportKey('raw', sigPubKey);
      const sigPubB64 = bytesToBase64Url(new Uint8Array(sigPubRaw));

      const fullRecipient = recipient + ';ed25519:' + sigPubB64;
      const identityBlob  = blob;

      // Encrypt with N=2^18 in the worker.
      const result = await runScryptWorker({ op: 'ENCRYPT', identityBlob, passphrase: pass });

      await store.set({ ageRecipient: fullRecipient, ageEncryptedIdentity: result.encryptedB64, contacts: {}, globalOn: true });
      await setSession(identityBlob);
      _sessionIdentity = identityBlob;
      _contacts = {};
      _globalOn = true;

      document.getElementById('import-blob').value        = '';
      document.getElementById('import-passphrase').value  = '';
      document.getElementById('import-passphrase2').value = '';
      clearImportDraft();

      await bgSend({ type: 'UNLOCK', identity: identityBlob });
      await bgSend({ type: 'RELOAD_DISCORD_TABS' });
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
    const data = await store.get(['contacts', 'globalOn']);
    _contacts = data.contacts || {};
    _globalOn = data.globalOn !== false;
    document.getElementById('global-toggle').checked = _globalOn;
    renderContacts();
    show('main');
  }

  document.getElementById('global-toggle').addEventListener('change', async (e) => {
    _globalOn = e.target.checked;
    await store.set({ globalOn: _globalOn });
    await bgSend({ type: 'CONTACTS_UPDATED' });
  });

  document.getElementById('btn-lock').addEventListener('click', async () => {
    await clearSession();
    _sessionIdentity = null;
    await bgSend({ type: 'RELOCK' });
    document.getElementById('passphrase-input').value = '';
    document.getElementById('unlock-error').hidden = true;
    // Keep btn-goto-setup visible — user has a stored keypair, they may want to reset.
    document.getElementById('btn-goto-setup').hidden = false;
    show('lock');
  });

  document.getElementById('btn-my-key').addEventListener('click', showMyKey);
  document.getElementById('btn-about').addEventListener('click', showAbout);

  // ─── Contact validation ───────────────────────────────────────────────────────

  // Validate a full age recipient string (age1… + ;ed25519:… suffix).
  // Returns null on success, error string on failure.
  async function validateRecipient(recipient) {
    if (!recipient.startsWith('age1'))
      return 'Public key must start with "age1…".';
    if (recipient.startsWith('AGE-SECRET-KEY-'))
      return 'That is a private key — paste their public key (age1…) instead.';
    if (!/;ed25519:[A-Za-z0-9_-]{40,}$/.test(recipient))
      return 'Public key must include an Ed25519 component (;ed25519:…). Share your full public key with the other party.';
    // Live test-encrypt to confirm the age1 part is valid.
    try {
      const test = new age.Encrypter();
      test.addRecipient(recipient.split(';')[0]);
      await test.encrypt(new TextEncoder().encode(''));
    } catch (e) {
      return 'Key validation failed: ' + e.message;
    }
    return null;
  }

  // Validate a contact's fields for add/edit.
  // editingId: the channelId being edited (null for new contacts) — excluded from
  // duplicate checks so editing without changes doesn't falsely report a conflict.
  function validateContactFields(channelId, username, recipient, editingId = null) {
    if (!channelId || !username || !recipient)
      return 'All fields are required.';
    if (!/^\d+$/.test(channelId) || channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID)
      return `Channel ID must be ${MIN_CHANNEL_ID}–${MAX_CHANNEL_ID} digits.`;
    if (username.length < MIN_USERNAME || username.length > MAX_USERNAME)
      return `Contact name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`;

    for (const [id, c] of Object.entries(_contacts)) {
      if (id === editingId) continue; // skip the contact being edited
      if (id === channelId)
        return 'A contact with this Channel ID already exists.';
      if (c.username === username)
        return `The name "${username}" is already used by another contact.`;
      if (c.ageRecipient === recipient)
        return 'This public key is already assigned to another contact.';
    }
    return null;
  }

  // ─── Contacts list ────────────────────────────────────────────────────────────

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
    if (Object.keys(_contacts).length >= MAX_CONTACTS) {
      alert(`Contact limit reached (${MAX_CONTACTS} max). Remove a contact before adding another.`);
      return;
    }
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

    const fieldErr = validateContactFields(channelId, username, recipient, null);
    if (fieldErr) { showErr(errEl, fieldErr); return; }

    const recipErr = await validateRecipient(recipient);
    if (recipErr)  { showErr(errEl, recipErr); return; }

    _contacts[channelId] = { username, ageRecipient: recipient, enabled: true };
    await store.set({ contacts: _contacts });
    await bgSend({ type: 'CONTACTS_UPDATED' });
    DRAFT_FIELDS.forEach(id => { document.getElementById(id).value = ''; });
    await clearDraft();
    await showMain();
  });

  // ─── Contact sheet ───────────────────────────────────────────────────────────

  async function openContactSheet(id) {
    _selectedId = id;
    const c    = _contacts[id];
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
    await bgSend({ type: 'CONTACTS_UPDATED' });
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
    await bgSend({ type: 'CONTACTS_UPDATED' });
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
    _editingId = _selectedId;   // capture before closeSheet() nulls _selectedId
    closeSheet();
    show('edit-contact');
  });

  document.getElementById('btn-back-edit').addEventListener('click', () => { _editingId = null; showMain(); });

  document.getElementById('btn-save-edit').addEventListener('click', async () => {
    const channelId = document.getElementById('edit-channel-id').value.trim();
    const username  = document.getElementById('edit-username').value.trim();
    const recipient = document.getElementById('edit-key').value.trim();
    const errEl     = document.getElementById('edit-contact-error');
    errEl.hidden    = true;

    // _editingId is set when the edit screen opens and survives closeSheet().
    // Pass it so the duplicate check skips this contact's own fields.
    const fieldErr = validateContactFields(channelId, username, recipient, _editingId);
    if (fieldErr) { showErr(errEl, fieldErr); return; }

    const recipErr = await validateRecipient(recipient);
    if (recipErr)  { showErr(errEl, recipErr); return; }

    // If the channelId changed, remove the old entry.
    if (_editingId && _editingId !== channelId) delete _contacts[_editingId];
    _contacts[channelId] = {
      username,
      ageRecipient: recipient,
      enabled: _contacts[channelId]?.enabled ?? _contacts[_editingId]?.enabled ?? true,
    };
    _editingId = null;
    await store.set({ contacts: _contacts });
    await bgSend({ type: 'CONTACTS_UPDATED' });
    await showMain();
  });

  // ─── Export contacts ──────────────────────────────────────────────────────────

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

  // ─── Import contacts ──────────────────────────────────────────────────────────

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

    if (entries.length > MAX_IMPORT_ROWS) {
      msgEl.textContent = `Import file too large — contains ${entries.length} entries (max ${MAX_IMPORT_ROWS}).`;
      modal.hidden = false;
      return;
    }

    // Detect intra-file duplicates: collect channelId, username, ageRecipient seen
    // within this import. Entries that duplicate a field within the file are
    // skipped entirely (neither the first nor the later copy is imported).
    const fileChannelIds   = new Map(); // value → first index seen
    const fileUsernames    = new Map();
    const fileRecipients   = new Map();
    const fileDupIndices   = new Set();

    entries.forEach((entry, idx) => {
      const { channelId, username, ageRecipient } = entry ?? {};
      if (!channelId || !username || !ageRecipient) return; // will be caught later
      if (fileChannelIds.has(channelId)) {
        fileDupIndices.add(idx);
        fileDupIndices.add(fileChannelIds.get(channelId));
      } else { fileChannelIds.set(channelId, idx); }
      if (fileUsernames.has(username)) {
        fileDupIndices.add(idx);
        fileDupIndices.add(fileUsernames.get(username));
      } else { fileUsernames.set(username, idx); }
      if (fileRecipients.has(ageRecipient)) {
        fileDupIndices.add(idx);
        fileDupIndices.add(fileRecipients.get(ageRecipient));
      } else { fileRecipients.set(ageRecipient, idx); }
    });

    let added = 0, updated = 0, skipped = 0, limitSkipped = 0;

    for (let idx = 0; idx < entries.length; idx++) {
      const entry = entries[idx] ?? {};
      const { channelId, username, ageRecipient, enabled } = entry;

      // Silently skip entries with invalid fields.
      if (!channelId || !username || !ageRecipient)                          { skipped++; continue; }
      if (!/^\d+$/.test(channelId)
          || channelId.length < MIN_CHANNEL_ID
          || channelId.length > MAX_CHANNEL_ID)                              { skipped++; continue; }
      if (typeof username !== 'string'
          || username.length < MIN_USERNAME
          || username.length > MAX_USERNAME)                                  { skipped++; continue; }
      if (typeof ageRecipient !== 'string'
          || !ageRecipient.startsWith('age1')
          || !/;ed25519:[A-Za-z0-9_-]{40,}$/.test(ageRecipient))            { skipped++; continue; }
      if (fileDupIndices.has(idx))                                           { skipped++; continue; }

      // Check against existing contacts for cross-file uniqueness.
      // Channel ID match → overwrite (update). Name or key match on a different
      // channel → skip.
      const existingById = Object.prototype.hasOwnProperty.call(_contacts, channelId);
      let crossConflict = false;
      for (const [id, c] of Object.entries(_contacts)) {
        if (id === channelId) continue; // same channel — will overwrite
        if (c.username === username || c.ageRecipient === ageRecipient) { crossConflict = true; break; }
      }
      if (crossConflict) { skipped++; continue; }

      // Respect the 1000-contact cap.
      if (!existingById && Object.keys(_contacts).length >= MAX_CONTACTS) { limitSkipped++; continue; }

      _contacts[channelId] = { username, ageRecipient, enabled: (enabled !== false) };
      existingById ? updated++ : added++;
    }

    await store.set({ contacts: _contacts });
    await bgSend({ type: 'CONTACTS_UPDATED' });
    if (_sessionIdentity) await bgSend({ type: 'UNLOCK', identity: _sessionIdentity });
    renderContacts();

    const parts = [];
    if (added)        parts.push(`${added} contact${added   !== 1 ? 's' : ''} added`);
    if (updated)      parts.push(`${updated} contact${updated !== 1 ? 's' : ''} updated`);
    if (skipped)      parts.push(`${skipped} skipped (invalid or duplicate)`);
    if (limitSkipped) parts.push(`${limitSkipped} skipped (contact limit reached)`);
    msgEl.textContent = 'Import complete — ' + (parts.join(', ') || 'nothing changed') + '.';
    modal.hidden = false;
  }

  document.getElementById('btn-import-contacts').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup/import-helper.html') });
  });

  let _importHelperTabId = null;

  function closeImportHelperTab() {
    if (_importHelperTabId === null) return;
    const id = _importHelperTabId;
    _importHelperTabId = null;
    chrome.tabs.remove(id, () => void chrome.runtime.lastError);
  }

  async function checkPendingImport() {
    try {
      if (!chrome.storage.session) return;
      const data = await new Promise(r =>
        chrome.storage.session.get(['pending_import', 'pending_import_tab'], r));
      if (!data.pending_import) return;
      _importHelperTabId = data.pending_import_tab ?? null;
      await new Promise(r => chrome.storage.session.remove(['pending_import', 'pending_import_tab'], r));
      await doImportContacts(data.pending_import);
    } catch {}
  }

  document.getElementById('btn-import-contacts-ok').addEventListener('click', () => {
    document.getElementById('modal-import-contacts').hidden = true;
    closeImportHelperTab();
  });

  window.addEventListener('unload', () => {
    if (!document.getElementById('modal-import-contacts').hidden) {
      closeImportHelperTab();
    }
  });

  // ─── My key screen ────────────────────────────────────────────────────────────

  document.getElementById('btn-back-key').addEventListener('click', showMain);

  async function showMyKey() {
    const { ageRecipient } = await store.get(['ageRecipient']);
    if (!ageRecipient) return;
    document.getElementById('my-key-box').textContent = ageRecipient;
    document.getElementById('my-key-fp').textContent = 'Computing fingerprint…';
    show('my-key');
    document.getElementById('my-key-fp').textContent = await keyFingerprint(ageRecipient);
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
    const btn  = document.getElementById('btn-copy-key');
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1800);
  });

  // ─── Export private key ───────────────────────────────────────────────────────

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
      const result = await runScryptWorker({ op: 'DECRYPT', encryptedB64: ageEncryptedIdentity, passphrase });
      const identity = result.identity;

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

  // ─── Keypair regeneration ─────────────────────────────────────────────────────

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
    await clearSession();
    _sessionIdentity = null;
    await bgSend({ type: 'RELOCK' });
    await bgSend({ type: 'RELOAD_DISCORD_TABS' });
    document.getElementById('setup-passphrase').value  = '';
    document.getElementById('setup-passphrase2').value = '';
    document.getElementById('setup-error').hidden      = true;
    show('setup');
  });

  // ─── Change passphrase (placeholder) ─────────────────────────────────────────

  document.getElementById('btn-change-passphrase').addEventListener('click', () => {
    // TODO: future release — re-encrypt stored key with new passphrase.
  });

  // ─── Utilities ────────────────────────────────────────────────────────────────

  function showErr(el, msg) { el.textContent = msg; el.hidden = false; }

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
    document.getElementById(id).addEventListener('click', () => { chrome.tabs.create({ url }); });
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
