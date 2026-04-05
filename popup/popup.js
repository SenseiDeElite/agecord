// popup.js — Discord Age Encryption
//
// Key storage : age identity (AGE-SECRET-KEY-1…) encrypted with a user passphrase
//               via age scrypt (N=18), stored as base64 in chrome.storage.local.
//               Contacts are encrypted with AES-GCM-256 using a key derived from
//               the identity via HKDF-SHA-256, so metadata is opaque at rest.
// Session     : decrypted identity is sent to background.js via SET_IDENTITY.
//               background.js generates a fresh non-extractable AES-GCM-256 key,
//               encrypts the identity blob with it, and stores only the ciphertext
//               in chrome.storage.session.  The encryption key lives exclusively
//               in the background heap and is never written to any storage.
//               If the service worker restarts the key is gone and the ciphertext
//               is permanently unreadable — user must re-enter their passphrase.
//               Content scripts never receive the raw identity — they ask the
//               background to encrypt/sign/decrypt on their behalf.
// Lockout     : 3 failed unlock attempts trigger a 10-minute lockout, matching
//               Linux pam_faillock defaults (deny=3, unlock_time=600).  Counter
//               lives in chrome.storage.local (survives popup closes and worker
//               restarts, resets on extension reload just as /var/run/faillock
//               resets on reboot).
// Performance : all scrypt operations (unlock, keygen, import, export verify)
//               run in a dedicated Web Worker (popup/scrypt-worker.js) so the
//               popup UI thread stays fully responsive during the 2–5 s scrypt
//               computation on Chromium.  A fresh worker is created per call.

(() => {
  'use strict';

  // ─── Storage helpers ────────────────────────────────────────────────────────
  const store = {
    get:    keys => new Promise(r => chrome.storage.local.get(keys, r)),
    set:    data => new Promise(r => chrome.storage.local.set(data, r)),
    remove: keys => new Promise(r => chrome.storage.local.remove(keys, r)),
  };

  // ─── Passphrase constants ────────────────────────────────────────────────────
  const PASSPHRASE_MIN_LEN = 20;
  const PASSPHRASE_MAX_LEN = 512;

  // ─── Lockout constants (matching Linux pam_faillock defaults) ────────────────
  //   deny=3          — lock after 3 consecutive failures
  //   unlock_time=600 — flat 10-minute lockout (no escalation; Linux doesn't use it)
  const LOCKOUT_MAX_ATTEMPTS = 3;
  const LOCKOUT_DURATION_MS  = 10 * 60 * 1000; // 600 s

  async function getLockoutState() {
    const { failCount = 0, lockUntil = 0 } = await store.get(['failCount', 'lockUntil']);
    return { failCount, lockUntil };
  }

  async function recordFailure() {
    const { failCount } = await getLockoutState();
    const newCount = failCount + 1;
    const update   = { failCount: newCount };
    if (newCount >= LOCKOUT_MAX_ATTEMPTS) {
      update.lockUntil = Date.now() + LOCKOUT_DURATION_MS;
    }
    await store.set(update);
    return newCount;
  }

  async function recordSuccess() {
    // Clear both counter and lockout timestamp on a successful unlock.
    await store.remove(['failCount', 'lockUntil']);
  }

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
  // then send the decrypted contacts and own recipient so content scripts can
  // request them from the background instead of reading local storage directly.
  // Finally signal Discord tabs only after both are confirmed.
  async function setIdentityInBackground(identity, contacts, ownRecipient) {
    await chrome.runtime.sendMessage({ type: 'SET_IDENTITY', identity });
    await chrome.runtime.sendMessage({ type: 'SET_CONTACTS', contacts, ownRecipient });
    // Background confirmed ready — now safe to wake Discord tabs.
    sendToDiscordTabs({ type: 'UNLOCK' });
  }

  // Push updated contacts to the background so content scripts see them immediately.
  async function pushContactsToBackground() {
    const { ageRecipient } = await store.get(['ageRecipient']);
    await chrome.runtime.sendMessage({
      type:         'SET_CONTACTS',
      contacts:     _contacts,
      ownRecipient: ageRecipient ?? null,
    });
  }

  // Tell background.js to wipe the identity.
  async function clearIdentityInBackground() {
    await chrome.runtime.sendMessage({ type: 'CLEAR_IDENTITY' });
  }

  // ─── Scrypt worker ───────────────────────────────────────────────────────────
  // Runs the expensive age scrypt operations (encrypt/decrypt) in a dedicated
  // Web Worker so the popup UI thread stays fully responsive during the 2–5 s
  // computation.  A fresh worker is created per call and terminated on completion
  // so there is no persistent worker state to worry about.

  function scryptInWorker(message) {
    return new Promise((resolve, reject) => {
      const worker = new Worker(chrome.runtime.getURL('popup/scrypt-worker.js'));

      // Safety net: scrypt N=18 should never exceed 60 s even on slow hardware.
      // If the worker hasn't responded by then, terminate it and reject.
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error('Scrypt worker timed out'));
      }, 60_000);

      worker.onmessage = ({ data }) => {
        clearTimeout(timeout);
        worker.terminate();
        if (data.ok) resolve(data);
        else reject(new Error(data.error ?? 'Worker failed'));
      };
      worker.onerror = (e) => {
        clearTimeout(timeout);
        worker.terminate();
        reject(new Error(e.message ?? 'Worker error'));
      };
      worker.postMessage(message);
    });
  }

  // ─── State ──────────────────────────────────────────────────────────────────
  let _contacts        = {};
  let _globalOn        = true;
  let _selectedId      = null;
  let _sessionIdentity = null;  // kept in popup memory for private key export only
  let _myKeyGeneration = 0;     // incremented on each showMyKey() call; guards stale async continuations

  // AES-GCM-256 key derived from the identity blob via HKDF-SHA-256.
  // Lives only in this popup's heap — never stored anywhere.
  // Wiped (set to null) on lock, popup close, or key regeneration.
  // Bound to the identity: contacts from one keypair cannot be decrypted
  // with a different keypair's derived key.
  let _contactsKey = null;

  // ─── Contacts encryption helpers ────────────────────────────────────────────
  // Key derivation: import the raw identity bytes as an HKDF base key, then
  // derive a dedicated AES-GCM-256 key with a fixed info label.  This is a
  // one-way derivation — knowing _contactsKey does not reveal the identity.

  async function deriveContactsKey(identityBlob) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(identityBlob),
      { name: 'HKDF' },
      false,               // non-extractable
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name:   'HKDF',
        hash:   'SHA-256',
        salt:   new Uint8Array(32),          // zero salt — domain separation is in info
        info:   new TextEncoder().encode('discord-age-encryption/contacts-key/v1'),
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,               // non-extractable
      ['encrypt', 'decrypt']
    );
  }

  async function encryptContacts(contacts) {
    if (!_contactsKey) throw new Error('Extension is locked.');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      _contactsKey,
      new TextEncoder().encode(JSON.stringify(contacts))
    );
    return bytesToBase64(new Uint8Array(iv)) + '.' + bytesToBase64(new Uint8Array(ct));
  }

  async function decryptContacts(encoded) {
    if (!_contactsKey) throw new Error('Extension is locked.');
    const dot = encoded.indexOf('.');
    if (dot === -1) throw new Error('Invalid contacts ciphertext format.');
    const iv = base64ToBytes(encoded.slice(0, dot));
    const ct = base64ToBytes(encoded.slice(dot + 1));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, _contactsKey, ct);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  // Persist _contacts to local storage, encrypted with the derived contacts key.
  async function saveContacts() {
    const encoded = await encryptContacts(_contacts);
    await store.set({ ageEncryptedContacts: encoded });
  }

  // ─── Screen router ──────────────────────────────────────────────────────────
  const screens = ['lock', 'setup', 'import', 'main', 'add-contact', 'edit-contact', 'my-key', 'change-pass', 'about'];
  const show = screenId =>
    screens.forEach(id => { document.getElementById(`screen-${id}`).hidden = (id !== screenId); });

  // ─── Session helpers ─────────────────────────────────────────────────────────
  // The popup only checks the age_unlocked flag to know if the session is live.
  // The identity itself is stored encrypted in background.js; the popup never
  // reads or holds the plaintext identity from session storage.
  // _sessionIdentity is kept in popup memory solely for the private key export UI.

  async function isSessionUnlocked() {
    try {
      if (chrome.storage.session) {
        const r = await new Promise(res => chrome.storage.session.get('age_unlocked', res));
        return r.age_unlocked === true;
      }
    } catch {}
    return false;
  }

  // ─── Boot ───────────────────────────────────────────────────────────────────

  async function boot() {
    const data = await store.get(['ageRecipient', 'ageEncryptedIdentity', 'ageEncryptedContacts', 'globalOn']);
    _globalOn = data.globalOn !== false;

    if (!data.ageRecipient || !data.ageEncryptedIdentity) {
      const hasDraft = await restoreImportDraft();
      show(hasDraft ? 'import' : 'setup');
      return;
    }

    // Contacts are encrypted at rest — we need the contacts key to read them.
    // The key is derived from the identity, which the background holds in memory.
    if (await isSessionUnlocked()) {
      try {
        // Re-derive the contacts key by fetching the identity from the background.
        // This covers the common case: popup closed and reopened while unlocked.
        const idResp = await chrome.runtime.sendMessage({ type: 'GET_IDENTITY' });
        if (idResp?.ok && idResp.identity) {
          _sessionIdentity = idResp.identity;
          _contactsKey = await deriveContactsKey(idResp.identity);
          const { ageEncryptedContacts } = await store.get(['ageEncryptedContacts']);
          if (ageEncryptedContacts) {
            try { _contacts = await decryptContacts(ageEncryptedContacts); }
            catch { _contacts = {}; }
          } else {
            _contacts = {};
          }
        }
      } catch { /* background not ready yet — contacts stay empty, UNLOCK will repopulate */ }
      // Re-signal Discord tabs in case any opened since last unlock.
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
    await store.remove(['ageRecipient', 'ageEncryptedIdentity', 'ageEncryptedContacts', 'globalOn', 'failCount', 'lockUntil']);
    await clearIdentityInBackground();
    _contacts        = {};
    _contactsKey     = null;
    _globalOn        = true;
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

    // ── Lockout check — before any crypto work ────────────────────────────────
    // This prevents the scrypt cost being paid on every rejected attempt, and
    // avoids timing side-channels from scrypt execution time.
    const { lockUntil } = await getLockoutState();
    if (Date.now() < lockUntil) {
      const minsLeft = Math.ceil((lockUntil - Date.now()) / 60000);
      showErr(errEl, `Too many failed attempts. Try again in ${minsLeft} minute${minsLeft !== 1 ? 's' : ''}.`);
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Unlocking…';

    try {
      const { ageEncryptedIdentity, ageEncryptedContacts } =
        await store.get(['ageEncryptedIdentity', 'ageEncryptedContacts']);
      if (!ageEncryptedIdentity) throw new Error('No keypair found.');

      // ── Decrypt identity in a Worker (keeps UI thread responsive) ────────────
      // scrypt N=18 takes 2–5 s on Chromium.  The worker runs age's async
      // decrypt path which yields every 10 ms so the event loop stays alive.
      let identity;
      try {
        const result = await scryptInWorker({
          op:           'DECRYPT',
          encryptedB64: ageEncryptedIdentity,
          passphrase,
        });
        identity = result.identity;
      } catch (workerErr) {
        // Re-throw with a message the wrong-passphrase detector can recognise.
        throw new Error('bad decrypt: ' + workerErr.message);
      }

      const identityLines = identity.split('\n');
      if (!identityLines[0].startsWith('AGE-SECRET-KEY-1'))
        throw new Error('Decrypted data is not a valid age identity.');
      if (!identityLines[1]?.startsWith('ed25519priv:'))
        throw new Error('Keypair missing Ed25519 signing key — please reset and generate a new keypair.');

      // ── Decrypt contacts using the HKDF-derived key ───────────────────────
      // Key derivation is cheap (no scrypt) — bound to the identity blob so
      // contacts from a different keypair are unreadable with this key.
      _contactsKey = await deriveContactsKey(identity);
      if (ageEncryptedContacts) {
        try {
          _contacts = await decryptContacts(ageEncryptedContacts);
        } catch {
          _contacts = {}; // corrupted or from an older format — start fresh
        }
      } else {
        _contacts = {};
      }

      await recordSuccess();
      const { ageRecipient } = await store.get(['ageRecipient']);
      await setIdentityInBackground(identity, _contacts, ageRecipient ?? null);
      _sessionIdentity = identity;
      document.getElementById('passphrase-input').value = '';
      await showMain();

    } catch (e) {
      const msg = e.message?.toLowerCase() ?? '';
      const isWrongPassphrase =
        msg.includes('bad') || msg.includes('decrypt') ||
        msg.includes('passphrase') || msg.includes('hmac');

      if (isWrongPassphrase) {
        const newCount  = await recordFailure();
        const remaining = LOCKOUT_MAX_ATTEMPTS - newCount;
        if (remaining <= 0) {
          showErr(errEl, 'Too many failed attempts. Locked for 10 minutes.');
        } else {
          showErr(errEl, `Wrong passphrase. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`);
        }
      } else {
        showErr(errEl, 'Unlock failed: ' + e.message);
      }
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
    if (p.length > PASSPHRASE_MAX_LEN) {
      strengthBar.style.width      = '100%';
      strengthBar.style.background = '#ed4245';
      strengthLbl.style.color      = '#ed4245';
      strengthLbl.textContent      = `Too long (max ${PASSPHRASE_MAX_LEN} chars)`;
      return;
    }
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
    if (p.length < PASSPHRASE_MIN_LEN) errs.push(`at least ${PASSPHRASE_MIN_LEN} characters`);
    if (p.length > PASSPHRASE_MAX_LEN) return `Passphrase must be at most ${PASSPHRASE_MAX_LEN} characters.`;
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

      // Encrypt identity blob in a Worker — scrypt N=18 keeps the UI alive.
      const encResult = await scryptInWorker({
        op:          'ENCRYPT',
        identityBlob,
        passphrase:  pass,
      });
      const encryptedB64 = encResult.encryptedB64;

      // Derive contacts key and encrypt the initial empty contacts map.
      // No scrypt cost — key is derived from the identity via HKDF.
      _contactsKey = await deriveContactsKey(identityBlob);
      _contacts    = {};
      const encryptedContacts = await encryptContacts({});

      await store.set({
        ageRecipient:          fullRecipient,
        ageEncryptedIdentity:  encryptedB64,
        ageEncryptedContacts:  encryptedContacts,
        globalOn:              true,
      });
      await setIdentityInBackground(identityBlob, {}, fullRecipient);
      _sessionIdentity = identityBlob;
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
    const blobRaw  = document.getElementById('import-blob').value.trim();
    const pass     = document.getElementById('import-passphrase').value;
    const pass2    = document.getElementById('import-passphrase2').value;
    const exportPw = document.getElementById('import-export-passphrase').value;
    const errEl    = document.getElementById('import-error');
    errEl.hidden   = true;

    const passErr = validatePassphrase(pass);
    if (passErr)        { showErr(errEl, passErr); return; }
    if (pass !== pass2) { showErr(errEl, 'Passphrases do not match.'); return; }
    if (!blobRaw)       { showErr(errEl, 'Paste your exported key blob first.'); return; }

    const btn = document.getElementById('btn-import');
    btn.hidden = true;
    document.getElementById('import-spinner').hidden = false;

    try {
      // ── Detect blob type ─────────────────────────────────────────────────
      // A plain blob starts with "AGE-SECRET-KEY-1" (two-line format).
      // An export-encrypted blob is a base64 string produced by the export flow
      // — it doesn't start with that prefix, so we try to decrypt it first.
      let blob;
      const isPlain = blobRaw.startsWith('AGE-SECRET-KEY-1');
      if (isPlain) {
        blob = blobRaw;
      } else {
        // Treat blobRaw as a v1: export-encrypted blob.
        if (!exportPw) {
          showErr(errEl, 'This looks like an encrypted export blob — enter the export passphrase below.');
          btn.hidden = false;
          document.getElementById('import-spinner').hidden = true;
          document.getElementById('import-export-pass-row').hidden = false;
          document.getElementById('import-export-passphrase').focus();
          return;
        }
        try {
          const decResult = await scryptInWorker({
            op:           'EXPORT_DECRYPT',
            encryptedB64: blobRaw,
            passphrase:   exportPw,
          });
          blob = decResult.identity;
        } catch {
          showErr(errEl, 'Could not decrypt blob — check the export passphrase and try again.');
          btn.hidden = false;
          document.getElementById('import-spinner').hidden = true;
          return;
        }
      }

      const lines = blob.split('\n');
      if (!lines[0].startsWith('AGE-SECRET-KEY-1')) {
        showErr(errEl, 'Invalid blob — line 1 must be an age secret key (AGE-SECRET-KEY-1…).');
        btn.hidden = false;
        document.getElementById('import-spinner').hidden = true;
        return;
      }
      if (!lines[1]?.startsWith('ed25519priv:')) {
        showErr(errEl, 'Invalid blob — line 2 must be an Ed25519 private key (ed25519priv:…).');
        btn.hidden = false;
        document.getElementById('import-spinner').hidden = true;
        return;
      }

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

      // Encrypt identity blob in a Worker — keeps spinner alive on Chromium.
      const encResult = await scryptInWorker({
        op:          'ENCRYPT',
        identityBlob,
        passphrase:  pass,
      });
      const encryptedB64 = encResult.encryptedB64;

      // Derive contacts key and create an encrypted empty contacts map.
      _contactsKey = await deriveContactsKey(identityBlob);
      _contacts    = {};
      const encryptedContacts = await encryptContacts({});

      await store.set({
        ageRecipient:          fullRecipient,
        ageEncryptedIdentity:  encryptedB64,
        ageEncryptedContacts:  encryptedContacts,
        globalOn:              true,
      });
      await setIdentityInBackground(identityBlob, {}, fullRecipient);
      _sessionIdentity = identityBlob;
      _globalOn = true;

      document.getElementById('import-blob').value             = '';
      document.getElementById('import-passphrase').value       = '';
      document.getElementById('import-passphrase2').value      = '';
      document.getElementById('import-export-passphrase').value = '';
      document.getElementById('import-export-pass-row').hidden  = true;
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
    // We render with the current in-memory state first.
    document.getElementById('global-toggle').checked = _globalOn;
    renderContacts();
    show('main');
    // Background refresh of globalOn — contacts live in _contacts (in-memory,
    // decrypted at unlock); reading them from storage would require another
    // decrypt round-trip and is unnecessary since all writes go through saveContacts().
    const data = await store.get(['globalOn']);
    _globalOn = data.globalOn !== false;
    document.getElementById('global-toggle').checked = _globalOn;
    renderContacts();
  }

  document.getElementById('global-toggle').addEventListener('change', async (e) => {
    _globalOn = e.target.checked;
    await store.set({ globalOn: _globalOn });
    await pushContactsToBackground();
    sendToDiscordTabs({ type: 'CONTACTS_UPDATED' });
  });

  document.getElementById('btn-lock').addEventListener('click', async () => {
    await clearIdentityInBackground();
    _sessionIdentity = null;
    _contactsKey     = null;
    _contacts        = {};
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
    await saveContacts();
    await pushContactsToBackground();
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
    await saveContacts();
    await pushContactsToBackground();
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
    await saveContacts();
    await pushContactsToBackground();
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
    await saveContacts();
    await pushContactsToBackground();
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

    await saveContacts();
    // CONTACTS_UPDATED tells content scripts to reload contacts from storage.
    // No need to re-send UNLOCK — the background already holds the identity
    // and content scripts are already unlocked.
    await pushContactsToBackground();
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
      // Verify passphrase by decrypting in a Worker — non-blocking on Chromium.
      const result = await scryptInWorker({
        op:           'DECRYPT',
        encryptedB64: ageEncryptedIdentity,
        passphrase,
      });
      const identity = result.identity;

      document.getElementById('export-passphrase-input').value = '';
      document.getElementById('modal-export-key').hidden = true;

      // Ask for an export passphrase to encrypt the blob before displaying.
      // This is stored temporarily for the next step.
      _pendingExportIdentity = identity;
      document.getElementById('export-blob-passphrase').value  = '';
      document.getElementById('export-blob-passphrase2').value = '';
      document.getElementById('export-blob-pass-error').hidden = true;
      document.getElementById('modal-export-set-pass').hidden  = false;
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

  // Temporary storage for the identity blob between the verify and encrypt steps.
  let _pendingExportIdentity = null;

  document.getElementById('btn-export-set-pass-cancel').addEventListener('click', () => {
    _pendingExportIdentity = null;
    document.getElementById('modal-export-set-pass').hidden = true;
  });

  document.getElementById('btn-export-set-pass-confirm').addEventListener('click', async () => {
    const exportPass  = document.getElementById('export-blob-passphrase').value;
    const exportPass2 = document.getElementById('export-blob-passphrase2').value;
    const errEl       = document.getElementById('export-blob-pass-error');
    const btn         = document.getElementById('btn-export-set-pass-confirm');
    errEl.hidden = true;

    const passErr = validatePassphrase(exportPass);
    if (passErr)               { showErr(errEl, passErr); return; }
    if (exportPass !== exportPass2) { showErr(errEl, 'Passphrases do not match.'); return; }
    if (!_pendingExportIdentity)    { showErr(errEl, 'Session expired, please try again.'); return; }

    btn.disabled = true;
    btn.textContent = 'Encrypting…';
    try {
      // Encrypt in the Worker using scryptAsync + AES-GCM.
      // scryptAsync yields periodically so the worker event loop stays alive
      // and doesn't get killed by the browser the way synchronous scrypt would.
      const encResult = await scryptInWorker({
        op:           'EXPORT_ENCRYPT',
        identityBlob: _pendingExportIdentity,
        passphrase:   exportPass,
      });
      if (!encResult?.ok) throw new Error(encResult?.error ?? 'Encryption failed');
      _pendingExportIdentity = null;
      document.getElementById('modal-export-set-pass').hidden = true;
      document.getElementById('export-key-blob').value = encResult.encryptedB64;
      document.getElementById('modal-export-display').hidden = false;
    } catch (e) {
      showErr(errEl, 'Encryption failed: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Encrypt & show';
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
    // Disable all contacts before losing the old keypair — new keypair gets empty contacts.
    Object.keys(_contacts).forEach(id => { _contacts[id].enabled = false; });
    await store.remove(['ageRecipient', 'ageEncryptedIdentity', 'ageEncryptedContacts']);
    await clearIdentityInBackground();
    _sessionIdentity = null;
    _contactsKey     = null;
    _contacts        = {};
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

  // ─── Change passphrase ───────────────────────────────────────────────────────
  // Re-encrypts the identity with a new passphrase.  Contacts do not need
  // re-encryption because they use an HKDF key derived from the identity blob
  // itself, not from the passphrase.

  document.getElementById('btn-change-pass').addEventListener('click', () => {
    document.getElementById('change-pass-current').value  = '';
    document.getElementById('change-pass-new').value     = '';
    document.getElementById('change-pass-new2').value    = '';
    document.getElementById('change-pass-error').hidden  = true;
    show('change-pass');
  });

  document.getElementById('btn-back-change-pass').addEventListener('click', showMain);

  const changePassNewEl  = document.getElementById('change-pass-new');
  const changePassBar    = document.getElementById('change-pass-strength-bar');
  const changePassLbl    = document.getElementById('change-pass-strength-label');

  changePassNewEl.addEventListener('input', () => {
    const p = changePassNewEl.value;
    if (p.length > PASSPHRASE_MAX_LEN) {
      changePassBar.style.width      = '100%';
      changePassBar.style.background = '#ed4245';
      changePassLbl.textContent      = `Too long (max ${PASSPHRASE_MAX_LEN} chars)`;
      changePassLbl.style.color      = '#ed4245';
      return;
    }
    let score = 0;
    if (p.length >= 20) score++;
    if (p.length >= 30) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[a-z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    const colors = ['#ed4245','#ed4245','#fee75c','#fee75c','#57f287','#57f287','#57f287'];
    changePassBar.style.width      = Math.round((score / 6) * 100) + '%';
    changePassBar.style.background = colors[score];
    changePassLbl.style.color      = colors[score];
    changePassLbl.textContent      = p.length ? ['Too short','Weak','Weak','Fair','Good','Strong','Very strong'][score] : '';
  });

  document.getElementById('btn-change-pass-confirm').addEventListener('click', async () => {
    const currentPass = document.getElementById('change-pass-current').value;
    const newPass     = document.getElementById('change-pass-new').value;
    const newPass2    = document.getElementById('change-pass-new2').value;
    const errEl       = document.getElementById('change-pass-error');
    const btn         = document.getElementById('btn-change-pass-confirm');
    errEl.hidden = true;

    if (!currentPass) { showErr(errEl, 'Enter your current passphrase.'); return; }
    const passErr = validatePassphrase(newPass);
    if (passErr)              { showErr(errEl, passErr); return; }
    if (newPass !== newPass2) { showErr(errEl, 'New passphrases do not match.'); return; }
    if (newPass === currentPass) { showErr(errEl, 'New passphrase must differ from current.'); return; }

    btn.disabled = true;
    btn.textContent = 'Changing…';
    try {
      const { ageEncryptedIdentity } = await store.get(['ageEncryptedIdentity']);
      if (!ageEncryptedIdentity) throw new Error('No keypair found.');

      // Verify current passphrase by decrypting.
      let identity;
      try {
        const decResult = await scryptInWorker({
          op:           'DECRYPT',
          encryptedB64: ageEncryptedIdentity,
          passphrase:   currentPass,
        });
        identity = decResult.identity;
      } catch {
        throw new Error('bad decrypt: wrong current passphrase');
      }

      // Re-encrypt with the new passphrase using scryptAsync in the Worker.
      const encResult = await scryptInWorker({
        op:           'EXPORT_ENCRYPT',
        identityBlob: identity,
        passphrase:   newPass,
      });
      if (!encResult?.ok) throw new Error(encResult?.error ?? 'Encryption failed');

      await store.set({ ageEncryptedIdentity: encResult.encryptedB64 });

      document.getElementById('change-pass-current').value = '';
      document.getElementById('change-pass-new').value     = '';
      document.getElementById('change-pass-new2').value    = '';

      // Show confirmation and return to main.
      await showMain();
      // Brief in-popup feedback via the lock button area — no toast needed.
    } catch (e) {
      const msg = e.message?.toLowerCase() ?? '';
      showErr(errEl,
        (msg.includes('bad') || msg.includes('decrypt') || msg.includes('passphrase') || msg.includes('hmac'))
          ? 'Wrong current passphrase.'
          : 'Failed: ' + e.message
      );
    } finally {
      btn.disabled = false;
      btn.textContent = 'Change passphrase';
    }
  });

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
