/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */

// popup.js — Agecord

// Storage: identity blob encrypted with Argon2id + XChaCha20-Poly1305,
//          stored as base64 in browser.storage.local (identity_blob).
// Session: decrypted identity in browser.storage.session; background keeps
//          memory copy and exposes only ML-DSA-87 signing key to content.
// Crypto:  handled by crypto-worker.js to keep UI responsive.
// Contacts: Argon2id key derivation in crypto-worker.js; raw key bytes sent
//           to background. Ciphertext uses XChaCha20-Poly1305 envelope.

// Model: contacts stored as { [uuid]: ContactEntry }.
//         uuid is stable v4 UUID generated on creation.
//         channelId is an entry field, not the map key.
//         v2 model introduced in 0.4.0.

'use strict';

(() => {

  // age-encryption and wasm named imports — resolved via dynamic import().
  let Encrypter, generateHybridIdentity, identityToRecipient;
  let ml_dsa87_keygen, ml_dsa87_verifying_key_from_seed, shake256;
  const cryptoReady = Promise.all([
    import(browser.runtime.getURL('lib/age.min.js')).then(m => {
      Encrypter              = m.Encrypter;
      generateHybridIdentity = m.generateHybridIdentity;
      identityToRecipient    = m.identityToRecipient;
    }),
    import(browser.runtime.getURL('lib/rustcrypto-wasm.min.js')).then(async m => {
      await m.init();
      ml_dsa87_keygen                  = m.ml_dsa87_keygen;
      ml_dsa87_verifying_key_from_seed = m.ml_dsa87_verifying_key_from_seed;
      shake256                         = m.shake256;
    }),
  ]);

  // ─── Constants ───────────────────────────────────────────────────────────────

  const MAX_CONTACTS    = 1000;
  const MAX_SERVERS     = 200;
  const MAX_CHANNEL_ID  = 20;   // chars
  const MIN_CHANNEL_ID  = 1;
  const MAX_USERNAME    = 32;
  const MIN_USERNAME    = 1;
  const MAX_GROUP_MEMBERS  = 10;
  const CONTACTS_VERSION   = 2;
  // Worst-case serialized export size for MAX_CONTACTS; reject oversized input
  // before JSON.parse rather than allowing arbitrary slack.
  const IMPORT_SIZE_LIMIT  = 5.4 * 1024 * 1024; // ~5.4 MiB

  // ─── Storage helpers ────────────────────────────────────────────────────────
  const store = {
    get:    keys => browser.storage.local.get(keys),
    set:    data => browser.storage.local.set(data),
    remove: keys => browser.storage.local.remove(keys),
  };

  async function getAgeRecipient() {
    const d = await store.get(['ageRecipient']);
    return d.ageRecipient ?? null;
  }

  // ─── Encrypted contacts storage ──────────────────────────────────────────────
  
// Contacts: encrypted at rest; local Argon2id key derivation/decryption.
// Writes use the background-held key to persist without re-prompting.

// State: _contacts is the unlocked in-memory source of truth.
// Session: _sessionPassphrase enables key re-derivation after background restart.

  let _sessionPassphrase = null;

  // Serialize saveContacts() calls so encryption and storage writes complete in
  // call order, preventing stale edits from overwriting newer ones.
  let _saveContactsChain = Promise.resolve();

  function saveContacts(contacts) {
    const run = () => saveContactsImpl(contacts);
    _saveContactsChain = _saveContactsChain.then(run, run);
    return _saveContactsChain;
  }

  async function saveContactsImpl(contacts) {
    const json = JSON.stringify(contacts);

    // Always update session storage immediately — this keeps the popup and content
    // scripts consistent even if the encrypted-at-rest write fails below.
    await setSessionContacts(contacts);

    const resp = await bgSend({ type: 'ENCRYPT_CONTACTS', json });
    if (resp?.ok) {
      await store.set({ contactsEnc: resp.ciphertextB64 });
      return;
    }

    // Background key unavailable (service-worker restarted, passphrase not cached).
    // Try to re-derive the key using the cached passphrase, then retry.
    if (_sessionPassphrase) {
      const identity = await getSessionIdentity();
      if (identity) {
        await bgUnlock(identity, _sessionPassphrase);
        const resp2 = await bgSend({ type: 'ENCRYPT_CONTACTS', json });
        if (resp2?.ok) {
          await store.set({ contactsEnc: resp2.ciphertextB64 });
          return;
        }
      }
    }

    // Could not encrypt — the encrypted blob on disk is stale until next full
    // unlock.  The session storage copy is up to date so the current session
    // is unaffected.  Log for diagnostics but don't surface to the user.
    console.warn('[age] saveContacts: could not update encrypted blob (background key unavailable).');
  }

  async function loadContacts() {
    const { contactsEnc } = await store.get(['contactsEnc']);
    if (!contactsEnc) {
      return {};
    }

    // Decrypts locally; no background key-availability retry is required.
    const passphrase = _sessionPassphrase ?? await getSessionPassphrase();
    if (passphrase) {
      try {
        const { contactsSaltB64 } = await store.get(['contactsSaltB64']);
        const { keyB64 } = await deriveContactsKey(passphrase, contactsSaltB64 ?? null);
        const parsed = await loadContactsWithKeyB64(keyB64);
        await setSessionContacts(parsed);
        return parsed;
      } catch (e) {
        console.warn('[age] loadContacts: local decrypt failed:', e?.message);
      }
    }

    // Fall back to the session-cached contacts if the passphrase is unavailable
    // or local decryption fails.
    try {
      const s = await browser.storage.session.get('age_contacts');
      if (s.age_contacts && typeof s.age_contacts === 'object') {
        return s.age_contacts;
      }
    } catch {}

    console.error('[age] loadContacts: no passphrase available and no session fallback.');
    return {};
  }

  // ─── Background messaging ────────────────────────────────────────────────────
  
  // All tab-relay operations go through the background service worker.

  function bgSend(msg) {
    // browser.runtime.sendMessage returns a Promise natively in MV3.
    // Swallow lastError (no listener on the other end during early boot) so the
    // promise rejects cleanly rather than throwing an uncaught extension error.
    return browser.runtime.sendMessage(msg).catch(e => {
      void e; // lastError consumed — callers already handle null/undefined responses
      return undefined;
    });
  }

  // Relay contacts + ageRecipient; content scripts cannot access session storage.
  // bgUnlock derives the Argon2id key and broadcasts identity + contacts.

  // refreshContacts defaults false. Only doUnlock() refreshes from storage;
  // other callers already hold authoritative in-memory _contacts, which may
  // contain unsaved or intentionally reset edits.
  async function bgUnlock(identity, passphrase, { refreshContacts = false } = {}) {
    const ageRecipient = await getAgeRecipient();
    let contactsKeyB64 = null;
    if (refreshContacts) _contactsFreshFromUnlock = false;
    if (passphrase) {
      try {
        const { contactsSaltB64 } = await store.get(['contactsSaltB64']);
        const { keyB64 } = await deriveContactsKey(passphrase, contactsSaltB64 ?? null);
        contactsKeyB64 = keyB64;
        if (refreshContacts) {
          // Local decryption keeps UNLOCK broadcasts from exposing an empty contact state.
          _contacts = await loadContactsWithKeyB64(keyB64);
          await setSessionContacts(_contacts);
          _contactsFreshFromUnlock = true;
        }
      } catch (e) {
        // Leave _contacts unchanged; showMain() retries local decryption when needed.
        console.warn('[age] bgUnlock: could not derive/decrypt contacts locally:', e?.message);
      }
    }
    return bgSend({ type: 'UNLOCK', identity, contactsKeyB64, contacts: _contacts, ageRecipient });
  }

  // bgUnlockResume: restores identity + contacts without key derivation.
  // Contacts key is derived lazily by ensureContactsKey() on first save.
    
  // Optimization: skip UNLOCK if background identity is still live.

  // Re-prime background state only after service-worker loss; tabs sync via REQUEST_UNLOCK.
  async function bgUnlockResume(identity) {
    const ping = await bgSend({ type: 'PING' }).catch(() => null);
    if (ping?.hasIdentity) return; // background still live — nothing to do
    const ageRecipient = await getAgeRecipient();
    return bgSend({ type: 'UNLOCK', identity, contactsKeyB64: null, contacts: _contacts, ageRecipient });
  }

  // Ensures the background holds the Argon2id contacts key, deriving it on demand.
  // Called once before any saveContacts() write — a no-op if the key is already live.
  async function ensureContactsKey() {
    const ping = await bgSend({ type: 'PING' });
    if (ping?.hasContactsKey) return;
    const passphrase = _sessionPassphrase ?? await getSessionPassphrase();
    if (!passphrase) throw new Error('Session passphrase unavailable — please lock and unlock again.');
    const identity = _sessionIdentity ?? await getSessionIdentity();
    if (!identity)  throw new Error('Session identity unavailable — please lock and unlock again.');
    await bgUnlock(identity, passphrase);
  }

  // Runs an async save operation with button feedback: disables the button,
  // updates its label, awaits the operation, then restores the original state.
  async function withSaveButton(btn, savingLabel, fn) {
    const originalText    = btn.textContent;
    const originalDisabled = btn.disabled;
    btn.disabled    = true;
    btn.textContent = savingLabel;
    try {
      await fn();
    } finally {
      btn.disabled    = originalDisabled;
      btn.textContent = originalText;
    }
  }

  async function bgContactsUpdated() {
    const ageRecipient = await getAgeRecipient();
    return bgSend({ type: 'CONTACTS_UPDATED', contacts: _contacts, ageRecipient });
  }

  // contactsByChannelId → Map<channelId, entry>, used for duplicate-channelId enforcement.
  function contactsByChannelId(contacts) {
    const m = new Map();
    for (const entry of Object.values(contacts)) {
      if (entry.channelId) m.set(entry.channelId, entry);
    }
    return m;
  }

  // ─── State ──────────────────────────────────────────────────────────────────
  
  let _contacts        = {};   // { [uuid]: ContactEntry }
  let _globalOn        = true;
  let _selectedId      = null; // uuid of the currently open contact sheet
  let _selectedGroupId = null; // uuid of the currently open group sheet
  let _selectedServerId= null; // uuid of the currently open server sheet
  let _editingId       = null; // uuid currently open in the edit screen
  let _sessionIdentity = null; // decrypted two-line identity blob, kept for export
  // Resolves once boot()'s fire-and-forget showMain() call has finished its
  // async contact-load/broadcast tail. checkPendingImport() awaits this so 
  // an import can't race loadContacts()'s reassignment of _contacts.
  let _mainReadyPromise = null;
  // Set by bgUnlock() when contacts were decrypted locally; showMain() consumes
  // it to skip redundant decryption. bgUnlockResume() never sets it.
  let _contactsFreshFromUnlock = false;
  
  // ─── UI helpers ──────────────────────────────────────────────────────────────

  const SVG_NS = 'http://www.w3.org/2000/svg';

  // <svg><use href="#id"/></svg> from the sprite in popup.html.
  function icon(id) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'ic');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `#${id}`);
    svg.append(use);
    return svg;
  }

  const AVATAR_HUES = [255, 30, 325, 170, 5, 235, 350, 95, 15, 245, 340, 45];
  function hueFor(id) {
    let h = 0;
    for (const ch of String(id)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return AVATAR_HUES[h % AVATAR_HUES.length];
  }
  const initialOf = name => (name ?? '').trim().charAt(0).toUpperCase() || '?';

  function setContactAvatar(el, contact) {
    el.textContent = initialOf(contact.username);
    el.style.setProperty('--ah', hueFor(contact.id));
  }

  // Avatar for any entry: initial in a circle (contact), group icon in a squircle,
  // server icon in an octagon. Group and server hues are fixed in CSS.
  function makeAvatar(entry, extraClass = '') {
    const type = entry.type ?? 'contact';
    const el = document.createElement('span');
    el.setAttribute('aria-hidden', 'true');
    if (type === 'group' || type === 'server') {
      el.className = `avatar is-${type} ${extraClass}`.trim();
      el.append(icon(type === 'group' ? 'i-group' : 'i-server'));
    } else {
      el.className = `avatar ${extraClass}`.trim();
      setContactAvatar(el, entry);
    }
    return el;
  }

  const memberCountLabel = n => `${n} member${n === 1 ? '' : 's'}`;
  function entrySub(entry) {
    const n = entry.memberIds?.length ?? 0;
    if (entry.type === 'group')  return `Group · ${memberCountLabel(n)}`;
    if (entry.type === 'server') return `Server · ${memberCountLabel(n)}`;
    return 'Direct message';
  }

  function renderFingerprint(el, text) {
    const groups = text.split(/\s+/).filter(Boolean);
    const isHex = groups.length > 1 && groups.every(g => /^[0-9A-F]{4}$/.test(g));
    el.classList.toggle('is-plain', !isHex);
    if (!isHex) { el.textContent = text; return; }
    el.replaceChildren();
    groups.forEach((g, i) => {
      if (i) el.append(' ');
      el.append(Object.assign(document.createElement('span'), { textContent: g }));
    });
  }

  // Master status line under the Encryption switch.
  function updateMasterSub() {
    const sub = $('master-sub');
    if ($('global-toggle').checked) {
      const n = Object.values(_contacts).filter(c => c.enabled && (c.type === 'contact' || !c.type || c.memberIds?.length > 0)).length;
      sub.textContent = `Armed for ${n} recipient${n === 1 ? '' : 's'}`;
    } else {
      sub.textContent = 'Paused. Messages send as plain text.';
    }
  }

  let _announceTimer = null;
  function announce(text) {
    const live = $('toast-live');
    clearTimeout(_announceTimer);
    live.textContent = '';
    _announceTimer = setTimeout(() => {
      live.textContent = text;
      _announceTimer = setTimeout(() => { live.textContent = ''; }, 3000);
    }, 60);
  }

  let _toastTimer = null;
  function showToast(text, isError = false) {
    const toast = $('toast');
    $('toast-text').textContent = text;
    toast.querySelector('use').setAttribute('href', isError ? '#i-x-circle' : '#i-check-circle');
    if (!toast.matches(':popover-open')) toast.showPopover();
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => { if (toast.matches(':popover-open')) toast.hidePopover(); }, 1900);
    announce(text);
  }

  document.addEventListener('pointermove', e => {
    const glass = e.target.closest?.('.glass');
    if (!glass) return;
    const r = glass.getBoundingClientRect();
    glass.style.setProperty('--px', `${e.clientX - r.left}px`);
    glass.style.setProperty('--py', `${e.clientY - r.top}px`);
  }, { passive: true });

  // ─── Screen router ──────────────────────────────────────────────────────────
  
  const SCREEN_DEPTH = {
    'lock': 0, 'setup': 0,
    'import': 1, 'main': 1,
    'add-contact': 2, 'edit-contact': 2, 'edit-group': 2, 'edit-server': 2, 'my-key': 2, 'about': 2,
  };
  const screens = Object.keys(SCREEN_DEPTH);
  let _currentScreen = null;

  const show = (screenId, dir) => {
    const swap = () => {
      screens.forEach(id => {
        const el = document.getElementById(`screen-${id}`);
        const hide = (id !== screenId);
        // Leaving a screen wipes its errors, so a hidden screen never holds stale
        // aria-invalid / message text (and re-entry starts clean).
        if (hide && !el.hidden) clearScreenErrors(el);
        el.hidden = hide;
      });
    };
    const from = _currentScreen;
    _currentScreen = screenId;
    if (!from || from === screenId || matchMedia('(prefers-reduced-motion: reduce)').matches) {
      swap();
      return;
    }
    document.documentElement.dataset.dir =
      dir ?? (SCREEN_DEPTH[screenId] < SCREEN_DEPTH[from] ? 'back' : 'fwd');
    document.startViewTransition(swap);
  };

  // Clears every form-level alert, field-error slot and aria-invalid inside a
  // container. Deliberately leaves #unlock-countdown alone: it is not an error
  // and its timer keeps running while the lock screen is hidden.
  function clearScreenErrors(container) {
    container.querySelectorAll('.form-error, .field-error').forEach(el => { el.textContent = ''; });
    container.querySelectorAll('[aria-invalid]').forEach(el => el.removeAttribute('aria-invalid'));
  }

  // ─── Error reporting (accessibility) ─────────────────────────────────────────
  
  // Field errors use aria-describedby and are read on focus; form-level errors use
  // a persistent role="alert" whose text changes to trigger screen reader announcements.
  const $ = id => document.getElementById(id);
  const MEMBERS_REQUIRED_MSG = 'Select at least 1 member.';
  // Form-level error slot of each member-picker mode (see applyMemberSelection).
  const MEMBER_ERROR_SLOT = {
    'add-group':   'add-contact-error',
    'add-server':  'add-contact-error',
    'edit-group':  'edit-group-error',
    'edit-server': 'edit-server-error',
  };

  // Form-level (non-field) errors. Text only; the slot is always rendered.
  // Save lives in the nav bar on the add/edit screens, so the slot under the fields
  // can sit below the fold: bring a new message into view.
  function showErr(el, msg) {
    el.textContent = msg;
    if (msg) el.scrollIntoView({ block: 'nearest' });
  }
  function clearErr(el)     { el.textContent = ''; }

  // Field-level. Slot id convention: `${field.id}-error`.
  function setFieldError(field, message) {
    const slot = $(`${field.id}-error`);
    if (slot) slot.textContent = message;
    if (message) field.setAttribute('aria-invalid', 'true');
    else field.removeAttribute('aria-invalid');
  }
  function clearFieldErrors(ids) {
    ids.forEach(id => { const f = $(id); if (f) setFieldError(f, ''); });
  }
  // err = { fieldId, message }. Marks the field, fills its slot, moves focus to it.
  function showFieldError(err) {
    const f = $(err.fieldId);
    setFieldError(f, err.message);
    f.focus();
  }
  // Lets async code throw an error that remembers which field it belongs to.
  const fieldError = (fieldId, message) => Object.assign(new Error(message), { fieldId });

  // Clear on edit: typing in an invalid field removes its error.
  document.addEventListener('input', e => {
    if (e.target.getAttribute?.('aria-invalid') === 'true') setFieldError(e.target, '');
  });

  // Always-present, visually hidden status nodes (one per spinner). Text is set
  // when work starts and cleared when it ends.
  function setStatus(id, text) { $(id).textContent = text; }

  // Field ids per form, used to wipe stale errors.
  const LOCK_FIELDS          = ['passphrase-input'];
  const SETUP_FIELDS         = ['setup-passphrase', 'setup-passphrase2'];
  const IMPORT_KEY_FIELDS    = ['import-blob', 'import-export-passphrase', 'import-passphrase', 'import-passphrase2'];
  const EXPORT_FIELDS        = ['export-passphrase-input', 'export-new-passphrase', 'export-new-passphrase2'];
  const CHANGE_PASS_FIELDS   = ['change-pass-current', 'change-pass-new', 'change-pass-new2'];
  const ADD_ENTRY_FIELDS     = ['contact-channel-id', 'contact-username', 'contact-key',
                                'group-channel-id', 'group-name',
                                'server-id-input', 'server-name'];
  const EDIT_CONTACT_FIELDS  = ['edit-channel-id', 'edit-username', 'edit-key'];
  const EDIT_GROUP_FIELDS    = ['edit-group-channel-id', 'edit-group-name'];
  const EDIT_SERVER_FIELDS   = ['edit-server-id-input', 'edit-server-name'];

  // Which field each validator error belongs to, per screen.
  const CONTACT_IDS_ADD  = { channel: 'contact-channel-id',    name: 'contact-username', key: 'contact-key' };
  const CONTACT_IDS_EDIT = { channel: 'edit-channel-id',       name: 'edit-username',    key: 'edit-key' };
  const GROUP_IDS_ADD    = { channel: 'group-channel-id',      name: 'group-name' };
  const GROUP_IDS_EDIT   = { channel: 'edit-group-channel-id', name: 'edit-group-name' };
  const SERVER_IDS_ADD   = { id: 'server-id-input',            name: 'server-name' };
  const SERVER_IDS_EDIT  = { id: 'edit-server-id-input',       name: 'edit-server-name' };

  // ─── Session helpers ─────────────────────────────────────────────────────────

  async function getSessionIdentity() {
    try {
      const r = await browser.storage.session.get(['age_unlocked', 'age_identity']);
      return r.age_unlocked === true ? (r.age_identity ?? null) : null;
    } catch {}
    return null;
  }

  async function setSession(identity) {
    try {
      await browser.storage.session.set({ age_unlocked: true, age_identity: identity });
    } catch {}
  }

  // Persisted so the background can recover after a SW restart without waiting for UNLOCK.
  async function setSessionRecipient(recipient) {
    try {
      if (recipient) await browser.storage.session.set({ age_recipient: recipient });
    } catch {}
  }

  // Persisted so the background can recover contacts after a SW restart without waiting for UNLOCK.
  async function setSessionContacts(contacts) {
    try {
      await browser.storage.session.set({ age_contacts: contacts });
    } catch {}
  }

  async function clearSession() {
    try {
      await browser.storage.session.remove(
        ['age_unlocked', 'age_identity', 'age_contacts', 'age_recipient',
         'age_passphrase', 'pending_unlock']);
    } catch {}
  }

  // Cached so saveContacts/loadContacts can re-derive the contacts key after a SW restart.
  async function setSessionPassphrase(passphrase) {
    try {
      if (passphrase) await browser.storage.session.set({ age_passphrase: passphrase });
    } catch {}
  }

  async function getSessionPassphrase() {
    try {
      const r = await browser.storage.session.get('age_passphrase');
      return r.age_passphrase ?? null;
    } catch {}
    return null;
  }

  // Tracks active unlock to let boot() handle mid-unlock dismissal.
  // Prevents partial unlock state from a closed popup race.
  async function setPendingUnlock(val) {
    try {
      await (val
        ? browser.storage.session.set({ pending_unlock: true })
        : browser.storage.session.remove('pending_unlock'));
    } catch {}
  }

  // ─── Crypto worker ───────────────────────────────────────────────────────────
  
  // New dedicated worker per call; terminated on completion.


  // transfer: ArrayBuffers moved to worker via transfer list.
  // Ownership transfers and buffers detach after send.
  function runCryptoWorker(msg, transfer = []) {
    return new Promise((resolve, reject) => {
      const workerUrl = browser.runtime.getURL('popup/crypto-worker.js');
      let worker;
      try {
        worker = new Worker(workerUrl, { type: 'module' });
      } catch (e) {
        reject(new Error('Could not start crypto worker: ' + e.message));
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
      worker.postMessage(msg, transfer);
    });
  }

  // Salt length mirrors crypto-worker.js ARGON2ID_DERIVE expectations.
  const CONTACTS_SALT_LEN = 16;

  // Derives a key over transferred ArrayBuffers. Returns base64 and
  // zeroes the intermediate typed array after encoding.
  async function deriveKeyB64(passphrase, saltBytesIn) {
    const passwordBytes = new TextEncoder().encode(passphrase);
    // saltBytesIn is transferred too, so hand the worker its own copy —
    // callers may still need the original (e.g. to persist or embed it).
    const saltBytes = saltBytesIn.slice();
    const { keyBytes } = await runCryptoWorker(
      { op: 'ARGON2ID_DERIVE', passwordBytes: passwordBytes.buffer, saltBytes: saltBytes.buffer },
      [passwordBytes.buffer, saltBytes.buffer],
    );
    const keyArr = new Uint8Array(keyBytes);
    const keyB64 = toB64(keyArr);
    keyArr.fill(0);
    return keyB64;
  }

  // Returns { keyB64, saltB64 }. Generates and persists a fresh salt if none provided.
  async function deriveContactsKey(passphrase, saltB64Opt) {
    let saltB64 = saltB64Opt;
    let saltBytes;
    if (!saltB64) {
      // Generate a fresh salt and persist it.
      saltBytes = crypto.getRandomValues(new Uint8Array(CONTACTS_SALT_LEN));
      saltB64   = toB64(saltBytes);
      await store.set({ contactsSaltB64: saltB64 });
    } else {
      saltBytes = fromB64(saltB64);
    }
    const keyB64 = await deriveKeyB64(passphrase, saltBytes);
    return { keyB64, saltB64 };
  }

  // Returns a base64-encoded v0x01 envelope (Argon2id + XChaCha20-Poly1305).
  // Worker IPC uses transferred bytes; base64 is applied only on return.
  async function encryptIdentityBlob(identityBlob, passphrase) {
    // Derive a fresh 32-byte key using a new random salt.
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));

    const passwordBytes = new TextEncoder().encode(passphrase);
    const { keyBytes } = await runCryptoWorker(
      { op: 'ARGON2ID_DERIVE', passwordBytes: passwordBytes.buffer, saltBytes: saltBytes.slice().buffer },
      [passwordBytes.buffer],
    );

    const plaintextBytes = new TextEncoder().encode(identityBlob);

    const { envelopeBytes } = await runCryptoWorker(
      {
        op: 'XCHACHA_ENCRYPT',
        keyBytes,
        plaintextBytes: plaintextBytes.buffer,
        saltBytes: saltBytes.buffer,
      },
      [keyBytes, plaintextBytes.buffer, saltBytes.buffer],
    );

    const envelopeArr = new Uint8Array(envelopeBytes);
    const envelopeB64 = toB64(envelopeArr);
    envelopeArr.fill(0);
    return envelopeB64;
  }

  // Decrypts a base64-encoded version-0x01 envelope; returns the raw identity string.
  async function decryptIdentityBlob(envelopeB64, passphrase) {
    const envBytes = fromB64(envelopeB64);

    // 1 (version) + 16 (Argon2id salt) + 1 (min ciphertext)
    if (envBytes.length < 18) {
      throw new Error('CORRUPT_BLOB');
    }

    if (envBytes[0] !== 0x01) {
      throw new Error('OUTDATED_FORMAT');
    }

    const saltBytes = envBytes.slice(1, 17);

    const passwordBytes = new TextEncoder().encode(passphrase);
    const { keyBytes } = await runCryptoWorker(
      { op: 'ARGON2ID_DERIVE', passwordBytes: passwordBytes.buffer, saltBytes: saltBytes.buffer },
      [passwordBytes.buffer, saltBytes.buffer],
    );

    const { plaintextBytes } = await runCryptoWorker(
      { op: 'XCHACHA_DECRYPT', keyBytes, envelopeBytes: envBytes.buffer },
      [keyBytes, envBytes.buffer],
    );

    const plaintextArr = new Uint8Array(plaintextBytes);
    const identity = new TextDecoder().decode(plaintextArr);
    plaintextArr.fill(0);
    return identity;
  }

  // Locally decrypts the contacts envelope with an existing key.
  // Unlike identity blobs, contacts store the salt separately.
  async function decryptContactsBlob(ciphertextB64, keyBytes) {
    const envBytes = fromB64(ciphertextB64);
    const { plaintextBytes } = await runCryptoWorker(
      { op: 'XCHACHA_DECRYPT_CONTACTS', keyBytes: keyBytes.buffer, envelopeBytes: envBytes.buffer },
      [keyBytes.buffer, envBytes.buffer],
    );
    const plaintextArr = new Uint8Array(plaintextBytes);
    const json = new TextDecoder().decode(plaintextArr);
    plaintextArr.fill(0);
    return JSON.parse(json);
  }

  // Locally decrypt contactsEnc with the given key.
  // Returns {} when unset; throws on decrypt or corruption errors.
  async function loadContactsWithKeyB64(keyB64) {
    const { contactsEnc } = await store.get(['contactsEnc']);
    if (!contactsEnc) return {};
    const keyBytes = fromB64(keyB64);
    return decryptContactsBlob(contactsEnc, keyBytes);
  }

  // ─── Boot ───────────────────────────────────────────────────────────────────

  async function boot() {
    const data = await store.get(['ageRecipient', 'identity_blob', 'ageEncryptedIdentity', 'globalOn']);
    _globalOn = data.globalOn !== false;

    const hasKey = !!(data.ageRecipient && (data.identity_blob || data.ageEncryptedIdentity));
    if (!hasKey) {
      const hasDraft = await restoreImportDraft();
      show(hasDraft ? 'import' : 'setup');
      return;
    }

    const identity = await getSessionIdentity();
    if (identity) {
      _sessionIdentity   = identity;
      _sessionPassphrase = await getSessionPassphrase();

      // Seed contacts from session storage so the list renders instantly on reopen,
      // before the background has re-established the contacts key.
      try {
        const s = await browser.storage.session.get('age_contacts');
        if (s.age_contacts && typeof s.age_contacts === 'object')
          _contacts = s.age_contacts;
      } catch {}

       // showMain() renders immediately; contact load/broadcast completes async.
       // Store promise so imports wait for loadContacts() to finish.
       // Prevents _contacts reassignment races from reverting imports.
      _mainReadyPromise = showMain();

      // Re-sync with the background in parallel; showMain's own loadContacts()
      // call will refresh the list once the key is available.
      bgUnlockResume(identity).catch(e =>
        console.warn('[age] bgUnlockResume failed:', e?.message));
    } else {
      // Handles popup dismissal during unlock.
      // Clears stale partial session data from racing doUnlock().
      // Restores clean lock state; user re-enters passphrase.
      try {
        const s = await browser.storage.session.get('pending_unlock');
        if (s.pending_unlock) await clearSession();
      } catch {}
      document.getElementById('btn-goto-setup').hidden = false;
      await showLockScreen();
    }
  }

  // ─── Dialog + confirm-alert helpers ──────────────────────────────────────────

  const openDialog = id => {
    const d = document.getElementById(id);
    if (d._closing) {            // reopened mid-exit: abort the pending close
      d._closing = null;
      d.removeAttribute('data-closing');
    }
    if (!d.open) d.showModal();
  };
  function closeDialogEl(d) {
    if (!d.open) return Promise.resolve();
    if (d._closing) return d._closing;
    d.setAttribute('data-closing', '');
    const exits = d.getAnimations()
      .filter(a => a instanceof CSSAnimation && a.animationName.endsWith('-out'));
    const done = Promise.allSettled(exits.map(a => a.finished)).then(() => {
      if (d._closing !== done) return;     // reopened meanwhile
      d._closing = null;
      d.removeAttribute('data-closing');
      d.close();
    });
    d._closing = done;
    return done;
  }
  // Resolves once the dialog has fully left. Callers that re-render the UI behind
  // a dialog, or switch screens, must await it so those changes don't play
  // underneath (or get captured into a view transition with) a closing dialog.
  const closeDialog = id => closeDialogEl(document.getElementById(id));
  // Runs fn after the dialog has fully left, unless it was reopened meanwhile.
  const afterDialogClosed = (id, fn) => closeDialog(id).then(() => {
    if (!document.getElementById(id).open) fn();
  });
  // Esc and light-dismiss (closedby="any") fire `cancel` and then close the dialog
  // natively. Take over: run the dialog's own cancel button for shared cleanup,
  // then close through the animated path.
  document.querySelectorAll('dialog').forEach(d => {
    d.addEventListener('cancel', e => {
      e.preventDefault();
      if (d.dataset.cancel) document.getElementById(d.dataset.cancel).click();
      closeDialogEl(d);
    });
  });

  // Requires typing CONFIRM before destructive actions.
  // Typing enables confirm; cancel closes; confirm runs the callback. Closing by any
  // route (cancel, confirm, Esc) wipes the typed word and re-disables confirm.
  // openBtn may be one id or several. IDs are explicit because the markup names
  // its alerts inconsistently.
  function wireConfirmModal({ openBtn, cancelBtn, confirmBtn, modal, input, onConfirm, confirmWord = 'CONFIRM' }) {
    const cancelEl  = document.getElementById(cancelBtn);
    const confirmEl = document.getElementById(confirmBtn);
    const modalEl   = document.getElementById(modal);
    const inputEl   = document.getElementById(input);

    [].concat(openBtn).forEach(id => {
      document.getElementById(id).addEventListener('click', () => openDialog(modal));
    });
    cancelEl.addEventListener('click', () => closeDialog(modal));
    // 'close' now fires only after the exit animation has finished.
    modalEl.addEventListener('close', () => {
      inputEl.value      = '';
      confirmEl.disabled = true;
    });
    inputEl.addEventListener('input', e => {
      confirmEl.disabled = (e.target.value !== confirmWord);
    });
    confirmEl.addEventListener('click', async () => {
      await closeDialog(modal);
      await onConfirm();
    });
  }

  // ─── Lock screen ─────────────────────────────────────────────────────────────

  document.getElementById('form-lock').addEventListener('submit', e => {
    e.preventDefault();
    doUnlock();
  });

  // resetToSetupScreen: shared teardown for reset-keypair and clear-all-data.
  
  // Clear passphrase fields unconditionally, including hidden fields.
  async function resetToSetupScreen() {
    await store.remove(['ageRecipient', 'identity_blob', 'ageEncryptedIdentity',
                        'contactsEnc', 'contactsSaltB64', 'contacts', 'globalOn',
                        'unlockAttempts', 'unlockLockedUntil', 'format_version']);
    await clearSession();
    _contacts          = {};
    _globalOn          = true;
    _sessionIdentity   = null;
    _sessionPassphrase = null;
    await bgSend({ type: 'RELOCK' });
    document.getElementById('btn-goto-setup').hidden   = true;
    document.getElementById('passphrase-input').value  = '';
    // Stops any running lockout countdown and clears its text, the lock-screen
    // error and the countdown (the lockout record was just removed above).
    setLockdownUI(0);
    clearFieldErrors(LOCK_FIELDS);
    document.getElementById('setup-passphrase').value  = '';
    document.getElementById('setup-passphrase2').value = '';
    clearErr(document.getElementById('setup-error'));
    clearFieldErrors(SETUP_FIELDS);
    updateStrength();
    show('setup', 'back');
  }

  wireConfirmModal({
    openBtn:    ['btn-goto-setup', 'btn-forgot'],
    cancelBtn:  'btn-reset-cancel',
    confirmBtn: 'btn-reset-confirm',
    modal:      'modal-reset-keypair',
    input:      'reset-confirm-input',
    onConfirm:  () => resetToSetupScreen(),
  });

  // ─── Passphrase lockdown ──────────────────────────────────────────────────────
  
  // 3 consecutive failures → 10-minute lock.
  // Lockout duration is fixed; counter resets after expiry.
  // State persists in browser.storage.local to survive popup restarts.
  // Keys: unlockAttempts (0–2), unlockLockedUntil (ms timestamp).
  const LOCKOUT_MAX_ATTEMPTS = 3;
  const LOCKOUT_DURATION_MS  = 10 * 60 * 1000; // 10 minutes

  let _lockCountdownInterval = null;
  // Track whether a lockdown UI is currently active so the doUnlock finally
  // block never accidentally re-enables the button while we're locked out.
  let _isLockedOut = false;

  function fmtCountdown(ms) {
    const total = Math.max(0, Math.ceil(ms / 1000));
    const m = Math.floor(total / 60);
    const s = total % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  }

  function setLockdownUI(lockedUntilMs) {
    const btn      = document.getElementById('btn-unlock');
    const errEl    = document.getElementById('unlock-error');
    const countdown = document.getElementById('unlock-countdown');
    const inp      = document.getElementById('passphrase-input');

    if (_lockCountdownInterval) { clearInterval(_lockCountdownInterval); _lockCountdownInterval = null; }

    if (!lockedUntilMs || Date.now() >= lockedUntilMs) {
      _isLockedOut = false;
      btn.disabled = false;
      inp.disabled = false;
      clearErr(errEl);
      clearErr(countdown);
      return;
    }

    _isLockedOut = true;
    btn.disabled    = true;
    btn.textContent = 'Unlock'; // reset from any in-progress label
    inp.disabled    = true;

    // The lockout is announced ONCE, through the alert slot. The ticking
    // countdown lives in its own role="timer" element (not a live region), so
    // it is readable on demand but silent while it updates every second.
    showErr(errEl, 'Too many failed attempts. Unlock is temporarily locked.');

    function tick() {
      const remaining = lockedUntilMs - Date.now();
      if (remaining <= 0) {
        clearInterval(_lockCountdownInterval);
        _lockCountdownInterval = null;
        _isLockedOut = false;
        btn.disabled = false;
        inp.disabled = false;
        clearErr(errEl);
        clearErr(countdown);
        // Clear the lockout record so the next 3 failures start a fresh lockout.
        store.set({ unlockAttempts: 0, unlockLockedUntil: 0 });
        return;
      }
      countdown.textContent = `Try again in ${fmtCountdown(remaining)}.`;
    }
    tick();
    _lockCountdownInterval = setInterval(tick, 1000);
  }

  // Announce stored attempts only on lock-screen open; don't mark the field invalid.
  // doUnlock() rechecks lockout on submit without repeating the announcement.
  async function checkLockdown({ announceAttempts = false } = {}) {
    const { unlockLockedUntil = 0, unlockAttempts = 0 } =
      await store.get(['unlockLockedUntil', 'unlockAttempts']);

    if (unlockLockedUntil && Date.now() < unlockLockedUntil) {
      // Active lockout — start the countdown UI.
      setLockdownUI(unlockLockedUntil);
      return true;
    }

    // Lockout may have expired while popup was closed — clear stale record.
    if (unlockLockedUntil && Date.now() >= unlockLockedUntil) {
      await store.set({ unlockAttempts: 0, unlockLockedUntil: 0 });
      return false;
    }

    // No lockout, but show how many attempts remain if any have been used.
    if (announceAttempts && unlockAttempts > 0) {
      const remaining = LOCKOUT_MAX_ATTEMPTS - unlockAttempts;
      showErr(
        document.getElementById('unlock-error'),
        `Wrong passphrase. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`
      );
    }

    return false;
  }

  // Show the lock screen and initialise its state (lockdown countdown or
  // remaining-attempts warning if applicable). Call this everywhere we
  // transition to the lock screen instead of bare show('lock').
  async function showLockScreen() {
    document.getElementById('passphrase-input').value = '';
    clearErr(document.getElementById('unlock-error'));
    clearErr(document.getElementById('unlock-countdown'));
    clearFieldErrors(LOCK_FIELDS);
    // Reset button state in case we're transitioning from an in-progress unlock.
    const btn = document.getElementById('btn-unlock');
    if (!_isLockedOut) {
      btn.disabled    = false;
      btn.textContent = 'Unlock';
    }
    document.getElementById('passphrase-input').disabled = _isLockedOut;
    show('lock');
    await checkLockdown({ announceAttempts: true });
  }

  async function recordFailedAttempt() {
    // Read-then-write atomically within the popup's single JS thread.
    const { unlockAttempts = 0 } = await store.get(['unlockAttempts']);
    const newCount = unlockAttempts + 1;
    if (newCount >= LOCKOUT_MAX_ATTEMPTS) {
      // Trigger a flat 10-minute lockout and reset the attempt counter so the
      // next session after the lockout starts fresh (no exponential escalation).
      const lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
      await store.set({ unlockAttempts: 0, unlockLockedUntil: lockedUntil });
      setLockdownUI(lockedUntil);
    } else {
      await store.set({ unlockAttempts: newCount, unlockLockedUntil: 0 });
      const remaining = LOCKOUT_MAX_ATTEMPTS - newCount;
      // A rejected entry: mark the passphrase field, fill its slot, focus it.
      showFieldError({
        fieldId: 'passphrase-input',
        message: `Wrong passphrase. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`,
      });
    }
  }

  async function clearFailedAttempts() {
    await store.set({ unlockAttempts: 0, unlockLockedUntil: 0 });
  }

  async function doUnlock() {
    await cryptoReady;
    // Synchronous re-entrance guard — must be the very first operation so that a
    // double-click cannot queue two concurrent Argon2id derivations before the
    // button has had a chance to disable itself.
    const btn = document.getElementById('btn-unlock');
    if (btn.disabled) return;
    btn.disabled    = true;
    btn.textContent = 'Unlocking…';

    // Always re-check persistent lockout state first — this prevents any bypass
    // by reloading the extension, since the lockout is stored in local storage.
    if (await checkLockdown()) {
      if (!_isLockedOut) { btn.disabled = false; btn.textContent = 'Unlock'; }
      return;
    }
    if (_isLockedOut) return;

    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase) { btn.disabled = false; btn.textContent = 'Unlock'; return; }

    const errEl = document.getElementById('unlock-error');
    clearErr(errEl);
    clearFieldErrors(LOCK_FIELDS);

    // _decryptFailed: set to true if we should count the attempt as a wrong
    // passphrase. ANY decryption failure means wrong passphrase or corrupt blob.
    let _decryptFailed = false;

    try {
      // Signal that an unlock is in progress. If the popup is dismissed before
      // we reach setSession() below, boot() on the next open will find this
      // flag, wipe any partial session data, and show a clean lock screen.
      await setPendingUnlock(true);

      const stored = await store.get(['identity_blob', 'ageEncryptedIdentity']);
      const blobB64 = stored.identity_blob || stored.ageEncryptedIdentity;
      if (!blobB64) throw new Error('No keypair found.');

      // Detect old format (not our 0x01 envelope).
      if (!stored.identity_blob && stored.ageEncryptedIdentity) {
        // Old format blob — surface migration error without counting as wrong passphrase.
        throw new Error('OUTDATED_FORMAT');
      }

      let identity;
      try {
        identity = await decryptIdentityBlob(blobB64, passphrase);
      } catch (workerErr) {
        if (workerErr.message === 'OUTDATED_FORMAT' ||
          workerErr.message === 'CORRUPT_BLOB') throw workerErr;
        // Any other decryption failure → wrong passphrase.
        _decryptFailed = true;
        throw workerErr;
      }

      const identityLines = identity.split('\n');
      if (!identityLines[0].startsWith('AGE-SECRET-KEY-1') &&
          !identityLines[0].startsWith('AGE-SECRET-KEY-PQ-1')) {
        _decryptFailed = true;
        throw new Error('Decrypted data is not a valid age identity.');
      }
      if (!identityLines[1]?.startsWith('mldsa87seed:')) {
        throw new Error('Keypair missing ML-DSA-87 seed — please reset and generate a new keypair.');
      }

      // Re-derive the ML-DSA-87 verifying key deterministically from the stored seed.
      const mldsaSeed = fromB64(identityLines[1].slice('mldsa87seed:'.length));
      const mldsaPub = ml_dsa87_verifying_key_from_seed(mldsaSeed);
      mldsaSeed.fill(0);
      const mldsaPubB64 = toB64(mldsaPub);

      // Rebuild the full recipient string if it was stored without the suffix
      let storedRecipient = await getAgeRecipient();
      if (storedRecipient && !storedRecipient.includes(';mldsa87:')) {
        storedRecipient = storedRecipient + ';mldsa87:' + mldsaPubB64;
        await store.set({ ageRecipient: storedRecipient });
      }

      await clearFailedAttempts();
      await setPendingUnlock(false); // unlock succeeded — clear the in-progress marker
      await setSession(identity);
      await setSessionRecipient(await getAgeRecipient());
      _sessionIdentity   = identity;
      _sessionPassphrase = passphrase;
      await setSessionPassphrase(passphrase);
      await store.set({ format_version: 2 });
      await bgUnlock(identity, passphrase, { refreshContacts: true });
      document.getElementById('passphrase-input').value = '';
      showMain();

    } catch (e) {
      if (e.message === 'CORRUPT_BLOB') {
        showErr(errEl, 'The stored key blob appears truncated or corrupt. Please re-import from a backup.');
      } else if (e.message === 'OUTDATED_FORMAT') {
        showErr(errEl,
          'Your identity format is outdated. Please regenerate your key or re-import from a backup.');
        await store.remove(['contactsSaltB64', 'contactsEnc']);
      } else if (_decryptFailed) {
        // Wrong passphrase — record against lockdown counter and clear the field.
        document.getElementById('passphrase-input').value = '';
        await recordFailedAttempt();
      } else {
        showErr(errEl, 'Unlock failed: ' + e.message);
      }
    } finally {
      // Only re-enable the button if we are NOT in an active lockout.
      if (!_isLockedOut) {
        btn.disabled = false;
        btn.textContent = 'Unlock';
      }
    }
  }

  // ─── Setup / keygen ──────────────────────────────────────────────────────────

  const setupPassEl = document.getElementById('setup-passphrase');
  const strengthBar = document.getElementById('strength-bar');
  const strengthLbl = document.getElementById('strength-label');
  // The visible label updates on every keystroke but is aria-hidden; screen
  // readers get the same text via #strength-status, debounced so it is not
  // re-announced for each character typed.
  const strengthStatus = document.getElementById('strength-status');
  let _strengthTimer = null;

  const setupSeal = document.getElementById('setup-seal');

  function updateStrength() {
    const p = setupPassEl.value;
    let score = 0;
    if (p.length >= 20) score++;
    if (p.length >= 30) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[a-z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    const level  = !p ? 0 : score <= 2 ? 1 : score === 3 ? 2 : score === 4 ? 3 : 4;
    const charge = level / 4;
    strengthBar.style.width = `${charge * 100}%`;
    strengthBar.classList.toggle('is-weak', level === 1);
    strengthLbl.classList.toggle('is-weak', level === 1);
    strengthLbl.textContent = ['', 'Weak', 'Fair', 'Good', 'Strong'][level];
    setupSeal.style.setProperty('--charge', charge);
    setupSeal.classList.toggle('is-lit', level === 4);
    clearTimeout(_strengthTimer);
    _strengthTimer = setTimeout(() => {
      strengthStatus.textContent = strengthLbl.textContent
        ? `Passphrase strength: ${strengthLbl.textContent}` : '';
    }, 500);
  }

  setupPassEl.addEventListener('input', updateStrength);

  // Rejects non-ASCII and control chars that could break JSON serialisation or protocol fields.
  function isPrintableAscii(s) {
    return /^[\x20-\x7E]+$/.test(s);
  }

  // Returns { fieldId, message } or null. The caller names the field because the
  // same rule applies to the setup, import, export and change-passphrase forms.
  function validatePassphrase(p, fieldId) {
    const errs = [];
    if (p.length < 20)           errs.push('at least 20 characters');
    if (!/[A-Z]/.test(p))        errs.push('an uppercase letter (A–Z)');
    if (!/[a-z]/.test(p))        errs.push('a lowercase letter (a–z)');
    if (!/[0-9]/.test(p))        errs.push('a number (0–9)');
    if (!/[^A-Za-z0-9]/.test(p)) errs.push('a special character (e.g. !&*)');
    return errs.length
      ? { fieldId, message: 'Passphrase must include: ' + errs.join(', ') + '.' }
      : null;
  }

  document.getElementById('form-setup').addEventListener('submit', async e => {
    e.preventDefault();
    await cryptoReady;
    const pass  = setupPassEl.value;
    const pass2 = document.getElementById('setup-passphrase2').value;
    const errEl = document.getElementById('setup-error');
    clearErr(errEl);
    clearFieldErrors(SETUP_FIELDS);

    const passErr = validatePassphrase(pass, 'setup-passphrase');
    if (passErr)        { showFieldError(passErr); return; }
    if (pass !== pass2) {
      setupPassEl.value = '';
      document.getElementById('setup-passphrase2').value = '';
      updateStrength();
      // Only the confirmation field is wrong.
      showFieldError({ fieldId: 'setup-passphrase2', message: 'Passphrases do not match.' });
      return;
    }

    document.getElementById('btn-generate').hidden  = true;
    document.getElementById('btn-show-import').hidden = true;
    document.getElementById('setup-spinner').hidden = false;
    setStatus('setup-status', 'Generating keypair... do not close this window.');

    try {
      const identity  = await generateHybridIdentity();
      const recipient = await identityToRecipient(identity);

      // Generate ML-DSA-87 keypair for message authentication.
      // Store only the 32-byte seed; derive verifying key on unlock.
      // Keeps identity blob compact and removes mldsa87pub: storage.
      const mldsaRaw     = ml_dsa87_keygen();              // 2624 bytes: seed(32)||vk(2592)
      const mldsaSeed    = mldsaRaw.slice(0, 32);          // 32-byte seed — the private key
      const mldsaPub     = mldsaRaw.slice(32);             // 2592-byte verifying key
      const mldsaSeedB64 = toB64(mldsaSeed);
      const mldsaPubB64  = toB64(mldsaPub);

      // Identity blob: AGE-SECRET-KEY-PQ-1… — age ML-KEM-768×X25519 hybrid private key.
      // mldsa87seed:<b64>   — 32-byte ML-DSA-87 seed.
  
      // Store seed only; derive ML-DSA-87 verifying key on unlock.
      // Reconstructs signing and recipient data without large key storage.
      const identityBlob  = identity + '\nmldsa87seed:' + mldsaSeedB64;
      const fullRecipient = recipient + ';mldsa87:' + mldsaPubB64;

      const envelopeB64 = await encryptIdentityBlob(identityBlob, pass);

      await store.set({ ageRecipient: fullRecipient, identity_blob: envelopeB64, globalOn: true, format_version: 2 });
      await setSession(identityBlob);
      await setSessionRecipient(fullRecipient);
      _sessionIdentity   = identityBlob;
      _sessionPassphrase = pass;
      await setSessionPassphrase(pass);
      _contacts = {};
      _globalOn = true;

      await bgUnlock(identityBlob, pass);
      await saveContacts({});
      await bgSend({ type: 'RELOAD_DISCORD_TABS' });

      // The passphrase has now been consumed (used to encrypt the identity
      // blob) — clear it from the DOM immediately rather than leaving it
      // sitting in these fields for the rest of the session.
      setupPassEl.value = '';
      document.getElementById('setup-passphrase2').value = '';
      updateStrength();

      await showMain();

    } catch (e) {
      showErr(document.getElementById('setup-error'), 'Key generation failed: ' + e.message);
    } finally {
      document.getElementById('btn-generate').hidden  = false;
      document.getElementById('btn-show-import').hidden = false;
      document.getElementById('setup-spinner').hidden = true;
      setStatus('setup-status', '');
    }
  });

  // ─── Import existing keypair ─────────────────────────────────────────────────

  const DRAFT_TTL = 5 * 60 * 1000; // aligned with SENSITIVE_FIELD_TTL below

  function makeDraftManager(sessionKey, fieldIds) {
    async function save() {
      const draft = { ts: Date.now() };
      fieldIds.forEach(id => { draft[id] = document.getElementById(id).value; });
      try { await browser.storage.session.set({ [sessionKey]: draft }); } catch {}
    }
    async function restore() {
      try {
        const result = await browser.storage.session.get(sessionKey);
        const draft = result[sessionKey];
        if (!draft || Date.now() - draft.ts > DRAFT_TTL) return false;
        fieldIds.forEach(id => { if (draft[id]) document.getElementById(id).value = draft[id]; });
        return fieldIds.some(id => document.getElementById(id).value.trim());
      } catch { return false; }
    }
    async function clear() {
      try { await browser.storage.session.remove(sessionKey); } catch {}
    }
    return { save, restore, clear };
  }

  const IMPORT_DRAFT_FIELDS = ['import-blob', 'import-export-passphrase', 'import-passphrase', 'import-passphrase2'];
  const { save: saveImportDraft, restore: restoreImportDraft, clear: clearImportDraft } =
    makeDraftManager('import_draft', IMPORT_DRAFT_FIELDS);

  IMPORT_DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveImportDraft));
  document.getElementById('btn-show-import').addEventListener('click', () => show('import'));
  document.getElementById('btn-back-import').addEventListener('click', () => {
    // Explicit cancel — the passphrases typed so far no longer serve any
    // purpose, so wipe both the visible fields and the autosaved draft
    // rather than letting them linger in session storage for the full TTL.
    IMPORT_DRAFT_FIELDS.forEach(id => { document.getElementById(id).value = ''; });
    clearImportDraft();
    show('setup');
  });

  document.getElementById('form-import').addEventListener('submit', async e => {
    e.preventDefault();
    await cryptoReady;
    const encryptedBlob  = document.getElementById('import-blob').value.trim();
    const exportPass     = document.getElementById('import-export-passphrase').value;
    const newPass        = document.getElementById('import-passphrase').value;
    const newPass2       = document.getElementById('import-passphrase2').value;
    const errEl          = document.getElementById('import-error');
    clearErr(errEl);
    clearFieldErrors(IMPORT_KEY_FIELDS);

    if (!encryptedBlob) {
      showFieldError({ fieldId: 'import-blob', message: 'Paste your encrypted private key blob first.' });
      return;
    }
    if (!exportPass) {
      showFieldError({ fieldId: 'import-export-passphrase',
                       message: 'Enter the export passphrase used when the blob was created.' });
      return;
    }

    const passErr = validatePassphrase(newPass, 'import-passphrase');
    if (passErr)           { showFieldError(passErr); return; }
    if (newPass !== newPass2) {
      document.getElementById('import-passphrase').value  = '';
      document.getElementById('import-passphrase2').value = '';
      saveImportDraft();
      // Only the confirmation field is wrong.
      showFieldError({ fieldId: 'import-passphrase2', message: 'Passphrases do not match.' });
      return;
    }

    const btn = document.getElementById('btn-import');
    btn.hidden = true;
    document.getElementById('import-spinner').hidden = false;
    setStatus('import-status', 'Importing... do not close this window.');

    // Set when the failure is specifically a wrong export passphrase, so the
    // outer catch can clear just that one field rather than all of them.
    let _wrongExportPass = false;

    try {
      // The export blob from "My Key → Export" is always encrypted with the
      // new XChaCha20 envelope format (version 0x01). 
      // Old exports will produce an OUTDATED_FORMAT error with a clear message.
      let identityBlob;
      try {
        identityBlob = await decryptIdentityBlob(encryptedBlob, exportPass);
      } catch (e) {
        // fieldError() tags each failure with the field it belongs to, so the
        // outer catch can mark exactly that field.
        if (e.message === 'CORRUPT_BLOB') {
          throw fieldError('import-blob',
            'The pasted blob appears truncated or corrupt. Please copy it again in full.');
        }
        if (e.message === 'OUTDATED_FORMAT') {
          throw fieldError('import-blob',
            'This export was created with an older version of the extension. ' +
            'Please regenerate your keypair on the original device and export again.');
        }
        _wrongExportPass = true;
        throw fieldError('import-export-passphrase',
          'Wrong export passphrase, or the blob is not a valid encrypted key export.');
      }

      const lines = identityBlob.split('\n');
      if (!lines[0].startsWith('AGE-SECRET-KEY-1') && !lines[0].startsWith('AGE-SECRET-KEY-PQ-1'))
        throw fieldError('import-blob',
          'Decrypted content is not a valid age identity (expected AGE-SECRET-KEY-PQ-1…).');
      if (!lines[1]?.startsWith('mldsa87seed:'))
        throw fieldError('import-blob',
          'Decrypted identity is missing an ML-DSA-87 seed (expected mldsa87seed:…).');

      const identity  = lines[0];
      const recipient = await identityToRecipient(identity);

      // Re-derive the ML-DSA-87 verifying key from the stored seed.
      const mldsaSeed    = fromB64(lines[1].slice('mldsa87seed:'.length));
      const mldsaPub     = ml_dsa87_verifying_key_from_seed(mldsaSeed);
      mldsaSeed.fill(0);
      const mldsaPubB64  = toB64(mldsaPub);
      const fullRecipient = recipient + ';mldsa87:' + mldsaPubB64;

      const envelopeB64 = await encryptIdentityBlob(identityBlob, newPass);

      await store.set({ ageRecipient: fullRecipient, identity_blob: envelopeB64, globalOn: true, format_version: 2 });
      await setSession(identityBlob);
      await setSessionRecipient(fullRecipient);
      _sessionIdentity   = identityBlob;
      _sessionPassphrase = newPass;
      await setSessionPassphrase(newPass);
      _contacts = {};
      _globalOn = true;

      document.getElementById('import-blob').value              = '';
      document.getElementById('import-export-passphrase').value = '';
      document.getElementById('import-passphrase').value        = '';
      document.getElementById('import-passphrase2').value       = '';
      clearImportDraft();

      await bgUnlock(identityBlob, newPass);
      await saveContacts({});
      await bgSend({ type: 'RELOAD_DISCORD_TABS' });
      await showMain();

    } catch (e) {
      if (_wrongExportPass) {
        document.getElementById('import-export-passphrase').value = '';
        saveImportDraft();
      }
      if (e.fieldId) showFieldError({ fieldId: e.fieldId, message: e.message });
      else           showErr(errEl, 'Import failed: ' + e.message);
    } finally {
      btn.hidden = false;
      document.getElementById('import-spinner').hidden = true;
      setStatus('import-status', '');
    }
  });

  // ─── Main screen ─────────────────────────────────────────────────────────────

  async function showMain() {
    const data = await store.get(['globalOn']);
    _globalOn = data.globalOn !== false;

    // Show the screen immediately — never let an async failure below block the
    // transition.  The passphrase field was already cleared by doUnlock; leaving
    // the lock screen visible after a successful crypto operation is a bug.
    document.getElementById('global-toggle').checked = _globalOn;
    document.getElementById('contacts-search').value = '';
    renderContacts();
    show('main');

    // Skip reload when bgUnlock() already decrypted and broadcast contacts;
    // otherwise load them for resumed sessions or failed unlock-time decryption.
    if (_contactsFreshFromUnlock) {
      _contactsFreshFromUnlock = false;
    } else {
      // Ignore loadContacts() failures so screen state remains unchanged.
      try {
        _contacts = await loadContacts();
      } catch (e) {
        console.warn('[age] showMain: loadContacts failed:', e?.message);
      }
    }
    renderContacts(); // re-render with the now-populated contacts list
    // Re-broadcast as a cheap, idempotent delivery backstop for missed UNLOCK messages.
    await bgContactsUpdated();
  }

  document.getElementById('global-toggle').addEventListener('change', async (e) => {
    _globalOn = e.target.checked;
    updateMasterSub();
    await store.set({ globalOn: _globalOn });
    await bgContactsUpdated();
  });

  document.getElementById('btn-lock').addEventListener('click', async () => {
    await clearSession();
    _sessionIdentity   = null;
    _sessionPassphrase = null;
    await bgSend({ type: 'RELOCK' });
    document.getElementById('btn-goto-setup').hidden = false;
    await showLockScreen();
  });

  document.getElementById('btn-my-key').addEventListener('click', showMyKey);
  document.getElementById('btn-about').addEventListener('click', showAbout);

  // ─── Contact validation ───────────────────────────────────────────────────────

  // Validate age recipient (age1pq1… + ;mldsa87:...).
  // Returns null on success, { fieldId, message } on failure (fieldId = the
  // public-key field the caller is validating).
  // Accepts only X25519+ML-KEM-768 hybrid keys.
  // Checks bech32 format, length bounds, and ML-DSA-87 suffix.
  // Structural validation only; no key agreement performed.
  function validateRecipient(recipient, fieldId) {
    const err = message => ({ fieldId, message });
    if (!recipient.startsWith('age1pq1'))
      return err('Public key must start with "age1pq1…" (X25519+MLKEM768 hybrid key).');
    if (recipient.startsWith('AGE-SECRET-KEY-'))
      return err('That is a private key — paste their public key (age1pq1…) instead.');
    if (!/;mldsa87:[A-Za-z0-9+/]+=*$/.test(recipient))
      return err('Public key must be the full key including the ML-DSA-87 component (age1pq1…;mldsa87:…).');
    // Validate the age1pq1 portion: bech32 charset including '1' (used as an
    // internal separator in the hybrid format), length ~1958 chars total.
    const agePart = recipient.split(';')[0];
    if (!/^age1pq1[ac-hj-np-z02-91]{50,1960}$/.test(agePart))
      return err('age1pq1... key appears malformed — check that it was copied correctly.');
    return null;
  }

  // Validate a contact's fields for add/edit.
  // editingUUID: the UUID being edited (null for new contacts) — excluded from
  // duplicate checks so editing without changes doesn't falsely report a conflict.
  // ids: { channel, name, key } — the field ids of the screen being validated.
  // Returns null, or { fieldId, message } naming the field at fault.
  function validateContactFields(channelId, username, recipient, editingUUID, ids) {
    const err = (fieldId, message) => ({ fieldId, message });
    if (!channelId) return err(ids.channel, 'Channel ID is required.');
    if (!username)  return err(ids.name,    'Name is required.');
    if (!recipient) return err(ids.key,     'Public key is required.');
    if (!/^\d+$/.test(channelId))
      return err(ids.channel, 'Channel ID must contain digits only.');
    if (channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID)
      return err(ids.channel, `Channel ID must be ${MIN_CHANNEL_ID}–${MAX_CHANNEL_ID} digits.`);
    if (username.length < MIN_USERNAME || username.length > MAX_USERNAME)
      return err(ids.name, `Contact name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`);
    if (!isPrintableAscii(username))
      return err(ids.name, 'Contact name must contain printable ASCII characters only.');

    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue; // skip the contact being edited
      if (c.channelId === channelId)
        return err(ids.channel, 'A contact with this Channel ID already exists.');
      if (c.username === username)
        return err(ids.name, `The name "${username}" is already used by another contact.`);
      if (c.ageRecipient === recipient)
        return err(ids.key, 'This public key is already assigned to another contact.');
    }
    return null;
  }

  // validateGroupFields: mirrors validateContactFields for group add/edit.
  // editingUUID: UUID being edited (null for new groups) — excluded from duplicate check.
  // ids: { channel, name } — field ids of the screen being validated.
  // Returns null, or { fieldId, message }.
  function validateGroupFields(channelId, name, editingUUID, ids) {
    const err = (fieldId, message) => ({ fieldId, message });
    if (!channelId) return err(ids.channel, 'Channel ID is required.');
    if (!/^\d+$/.test(channelId) || channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID)
      return err(ids.channel, `Channel ID must be ${MIN_CHANNEL_ID}–${MAX_CHANNEL_ID} digits.`);
    if (!name || name.length < MIN_USERNAME || name.length > MAX_USERNAME)
      return err(ids.name, `Name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`);
    if (!isPrintableAscii(name)) return err(ids.name, 'Name must contain printable ASCII characters only.');
    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue;
      if (c.channelId === channelId) return err(ids.channel, 'A contact or group with this Channel ID already exists.');
    }
    return null;
  }

  // validateServerFields: mirrors validateContactFields for server add/edit.
  // editingUUID: UUID being edited (null for new servers) — excluded from duplicate check.
  // ids: { id, name } — field ids of the screen being validated.
  // Returns null, or { fieldId, message }.
  function validateServerFields(serverId, name, editingUUID, ids) {
    const err = (fieldId, message) => ({ fieldId, message });
    if (!serverId || !/^\d{1,20}$/.test(serverId)) return err(ids.id, 'Server ID must be 1–20 digits.');
    if (!name || name.length < MIN_USERNAME || name.length > MAX_USERNAME)
      return err(ids.name, `Name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`);
    if (!isPrintableAscii(name)) return err(ids.name, 'Name must contain printable ASCII characters only.');
    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue;
      if (c.type === 'server' && c.serverId === serverId) return err(ids.id, 'A server with this Server ID already exists.');
    }
    return null;
  }

  // ─── Contacts list ────────────────────────────────────────────────────────────

  // query defaults to the search box so re-renders after a toggle keep the filter.
  function renderContacts(query = $('contacts-search').value) {
    const list  = document.getElementById('contacts-list');
    const empty = document.getElementById('no-contacts');
    list.replaceChildren();

    const q = query.trim().toLowerCase();
    const entries = Object.values(_contacts).filter(c => {
      if (q) {
        const label = (c.type === 'contact' || !c.type) ? c.username : c.name;
        return label?.toLowerCase().includes(q);
      }
      return true;
    });

    entries.sort((a, b) => {
      const la = ((a.type === 'contact' || !a.type) ? a.username : a.name) ?? '';
      const lb = ((b.type === 'contact' || !b.type) ? b.username : b.name) ?? '';
      return la.localeCompare(lb, undefined, { sensitivity: 'base' });
    });

    list.hidden  = entries.length === 0;
    empty.hidden = entries.length > 0;
    $('no-contacts-title').textContent = q ? 'No matches' : 'No contacts yet';
    $('no-contacts-msg').textContent   = q
      ? 'Nothing matches your search. Add a new entry to start encrypting.'
      : 'Add a new entry to start encrypting.';

    entries.forEach(c => {
      const uuid = c.id;
      const type = c.type ?? 'contact';
      const label = type === 'contact' ? c.username : c.name;

      // A real <button> so rows are keyboard-focusable and announced as actionable.
      // Phrasing content only (a <button> may not contain <div>).
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'row';

      const title = Object.assign(document.createElement('span'), { className: 'row-title', textContent: label });
      const sub   = Object.assign(document.createElement('span'), { className: 'row-sub',   textContent: entrySub({ ...c, type }) });
      const main  = Object.assign(document.createElement('span'), { className: 'row-main' });
      main.append(title, sub);

      // Lit lock = encryption on for this entry. The glyph differs too, so the state
      // is never colour alone.
      const mark = document.createElement('span');
      const on = c.enabled && (type === 'contact' || c.memberIds?.length > 0);
      mark.className = on ? 'lockmark is-on' : 'lockmark';
      mark.setAttribute('role', 'img');
      mark.setAttribute('aria-label', on ? 'Encryption on' : 'Encryption off');
      mark.append(icon(on ? 'i-lock' : 'i-lock-open'));

      row.append(makeAvatar({ ...c, type }), main, mark);
      row.addEventListener('click', () => {
        if (type === 'group')  openGroupSheet(uuid);
        else if (type === 'server') openServerSheet(uuid);
        else openContactSheet(uuid);
      });
      list.appendChild(row);
    });
    updateMasterSub();
  }

  document.getElementById('contacts-search').addEventListener('input', e => {
    renderContacts(e.target.value);
  });

  // ─── FAB / unified add screen ─────────────────────────────────────────────────

  const addType = () => document.querySelector('input[name="add-type"]:checked').value;

  function resetAddScreen() {
    document.getElementById('add-type-contact').checked = true;
    document.getElementById('add-fields-contact').hidden = false;
    document.getElementById('add-fields-group').hidden   = true;
    document.getElementById('add-fields-server').hidden  = true;
    clearErr(document.getElementById('add-contact-error'));
    clearFieldErrors(ADD_ENTRY_FIELDS);
    DRAFT_FIELDS.forEach(id => { document.getElementById(id).value = ''; });
    resetGroupForm('add');
    resetServerForm('add');
  }

  document.getElementById('btn-add-contact').addEventListener('click', async () => {
    resetAddScreen();
    const channelId = await inferDmChannelId();
    if (channelId) document.getElementById('contact-channel-id').value = channelId;
    show('add-contact');
  });

  document.getElementById('add-type').addEventListener('change', async (e) => {
    const type = e.target.value;
    document.getElementById('add-fields-contact').hidden = type !== 'contact';
    document.getElementById('add-fields-group').hidden   = type !== 'group';
    document.getElementById('add-fields-server').hidden  = type !== 'server';
    clearErr(document.getElementById('add-contact-error'));
    clearFieldErrors(ADD_ENTRY_FIELDS);
    if (type === 'contact') {
      const channelId = await inferDmChannelId();
      if (channelId) document.getElementById('contact-channel-id').value = channelId;
    } else if (type === 'group') {
      const channelId = await inferDmChannelId();
      if (channelId) document.getElementById('group-channel-id').value = channelId;
    } else if (type === 'server') {
      const serverId = await inferServerId();
      if (serverId) document.getElementById('server-id-input').value = serverId;
    }
  });

  // ─── Add contact / group / server ─────────────────────────────────────────────

  const DRAFT_FIELDS = ['contact-channel-id', 'contact-username', 'contact-key'];
  const { save: saveDraft, restore: restoreDraft, clear: clearDraft } =
    makeDraftManager('add_contact_draft', DRAFT_FIELDS);

  DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveDraft));

  // Require the Discord stable channel hostname; host permission already provides tab.url access.
  const DM_CHANNEL_URL_PATTERN = new URLPattern({
    protocol: 'https',
    hostname: 'discord.com',
    pathname: '/channels/@me/:channelId(\\d+)',
  });
  const SERVER_CHANNEL_URL_PATTERN = new URLPattern({
    protocol: 'https',
    hostname: 'discord.com',
    pathname: '/channels/:serverId(\\d+)/:channelId(\\d+)',
  });

  function inferFromTab(pattern, groupName) {
    return async () => {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      const url = tabs[0]?.url;
      if (!url) return null;
      // exec() throws on URLs it can't parse at all (e.g. "about:blank");
      // treat that the same as a non-match.
      let m;
      try { m = pattern.exec(url); } catch { return null; }
      return m ? m.pathname.groups[groupName] : null;
    };
  }

  // inferDmChannelId: extracts the channel ID from DM URLs only
  //   (/channels/@me/<id>).  Returns null for server channel URLs
  //   (/channels/<serverId>/<channelId>) — use inferServerId for those.
  const inferDmChannelId = inferFromTab(DM_CHANNEL_URL_PATTERN, 'channelId');
  const inferServerId    = inferFromTab(SERVER_CHANNEL_URL_PATTERN, 'serverId');

  document.getElementById('btn-back-add').addEventListener('click', async () => {
    await clearDraft();
    resetAddScreen();
    showMain();
  });

  document.getElementById('btn-save-contact').addEventListener('click', async () => {
    const type  = addType();
    const errEl = document.getElementById('add-contact-error');
    clearErr(errEl);
    clearFieldErrors(ADD_ENTRY_FIELDS);

    if (type === 'contact') {
      const channelId = document.getElementById('contact-channel-id').value.trim();
      const username  = document.getElementById('contact-username').value.trim();
      const recipient = document.getElementById('contact-key').value.trim();

      const fieldErr = validateContactFields(channelId, username, recipient, null, CONTACT_IDS_ADD);
      if (fieldErr) { showFieldError(fieldErr); return; }
      const recipErr = validateRecipient(recipient, CONTACT_IDS_ADD.key);
      if (recipErr)  { showFieldError(recipErr); return; }

      const contactCount = Object.values(_contacts).filter(c => c.type === 'contact' || !c.type).length;
      if (contactCount >= MAX_CONTACTS) { showErr(errEl, `Contact limit reached (${MAX_CONTACTS} max).`); return; }

      const uuid = crypto.randomUUID();
      _contacts[uuid] = { id: uuid, type: 'contact', channelId, username, ageRecipient: recipient, enabled: true };

    } else if (type === 'group') {
      const channelId = document.getElementById('group-channel-id').value.trim();
      const name      = document.getElementById('group-name').value.trim();

      const groupErr = validateGroupFields(channelId, name, null, GROUP_IDS_ADD);
      if (groupErr) { showFieldError(groupErr); return; }
      if (_groupAddMembers.length < 1) {
        // No single input is at fault: form-level message, focus the picker button.
        showErr(errEl, MEMBERS_REQUIRED_MSG);
        document.getElementById('btn-group-pick-members').focus();
        return;
      }

      const uuid = crypto.randomUUID();
      _contacts[uuid] = { id: uuid, type: 'group', channelId, name, memberIds: _groupAddMembers, enabled: true };

    } else if (type === 'server') {
      const serverId = document.getElementById('server-id-input').value.trim();
      const name     = document.getElementById('server-name').value.trim();

      const serverErr = validateServerFields(serverId, name, null, SERVER_IDS_ADD);
      if (serverErr) { showFieldError(serverErr); return; }
      const serverCount = Object.values(_contacts).filter(c => c.type === 'server').length;
      if (serverCount >= MAX_SERVERS) { showErr(errEl, `Server limit reached (${MAX_SERVERS} max).`); return; }
      if (_serverAddMembers.length < 1) {
        showErr(errEl, MEMBERS_REQUIRED_MSG);
        document.getElementById('btn-server-pick-members').focus();
        return;
      }

      const uuid = crypto.randomUUID();
      _contacts[uuid] = { id: uuid, type: 'server', serverId, name, memberIds: _serverAddMembers, enabled: true };
    }

    const saveBtn = document.getElementById('btn-save-contact');
    await withSaveButton(saveBtn, 'Saving…', async () => {
      await ensureContactsKey();
      await saveContacts(_contacts);
      await bgContactsUpdated();
      await clearDraft();
      resetAddScreen();
      await showMain();
      showToast('Saved');
    });
  });

  // ─── Contact sheet ───────────────────────────────────────────────────────────

  async function openContactSheet(uuid) {
    _selectedId = uuid;
    const c    = _contacts[uuid];
    const fpEl = document.getElementById('sheet-contact-fp');
    setContactAvatar(document.getElementById('sheet-contact-avatar'), c);
    document.getElementById('sheet-contact-name').textContent = c.username;
    document.getElementById('sheet-contact-toggle').checked   = c.enabled;
    renderFingerprint(fpEl, 'Computing fingerprint…');
    openDialog('sheet-contact');
    renderFingerprint(fpEl, await keyFingerprint(c.ageRecipient));
  }

  // Selection state is cleared immediately; the returned promise resolves when the
  // sheet has finished sliding away. Callers that re-render the list or switch
  // screens must await it so those changes don't play underneath the closing sheet.
  function closeSheet() {
    const done = Promise.all([
      closeDialog('sheet-contact'),
      closeDialog('sheet-group'),
      closeDialog('sheet-server'),
    ]);
    _selectedId       = null;
    _selectedGroupId  = null;
    _selectedServerId = null;
    return done;
  }

  document.getElementById('btn-close-sheet').addEventListener('click', closeSheet);

  document.getElementById('sheet-contact-toggle').addEventListener('change', async (e) => {
    if (!_selectedId) return;
    _contacts[_selectedId].enabled = e.target.checked;
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();
  });

  document.getElementById('btn-delete-contact').addEventListener('click', () => {
    if (!_selectedId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedId].username}" and their public key will be permanently removed.`;
    openDialog('modal-delete-contact');
  });

  document.getElementById('btn-delete-cancel').addEventListener('click', () => {
    closeDialog('modal-delete-contact');
  });

  document.getElementById('btn-delete-confirm').addEventListener('click', async () => {
    closeDialog('modal-delete-contact');
    if (_selectedId) {
      const deletedId = _selectedId;
      delete _contacts[deletedId];
      // Remove the deleted contact from any group/server member lists.
      for (const entry of Object.values(_contacts)) {
        if (Array.isArray(entry.memberIds)) {
          entry.memberIds = entry.memberIds.filter(id => id !== deletedId);
          // No recipients left: force encryption off until the user adds a contact.
          if (entry.memberIds.length === 0) entry.enabled = false;
        }
      }
    } else if (_selectedGroupId) {
      delete _contacts[_selectedGroupId];
    } else if (_selectedServerId) {
      delete _contacts[_selectedServerId];
    } else {
      return;
    }
    await saveContacts(_contacts);
    await bgContactsUpdated();
    await closeSheet();
    renderContacts();
    showToast('Deleted');
  });

  document.getElementById('btn-edit-contact').addEventListener('click', async () => {
    if (!_selectedId) return;
    const c = _contacts[_selectedId];
    document.getElementById('edit-channel-id').value = c.channelId;
    document.getElementById('edit-username').value   = c.username;
    document.getElementById('edit-key').value        = c.ageRecipient;
    clearErr(document.getElementById('edit-contact-error'));
    clearFieldErrors(EDIT_CONTACT_FIELDS);
    _editingId = _selectedId;
    await closeSheet();
    show('edit-contact');
  });

  document.getElementById('btn-back-edit').addEventListener('click', () => { _editingId = null; showMain(); });

  document.getElementById('btn-save-edit').addEventListener('click', async () => {
    const channelId = document.getElementById('edit-channel-id').value.trim();
    const username  = document.getElementById('edit-username').value.trim();
    const recipient = document.getElementById('edit-key').value.trim();
    const errEl     = document.getElementById('edit-contact-error');
    clearErr(errEl);
    clearFieldErrors(EDIT_CONTACT_FIELDS);

    const fieldErr = validateContactFields(channelId, username, recipient, _editingId, CONTACT_IDS_EDIT);
    if (fieldErr) { showFieldError(fieldErr); return; }

    const recipErr = validateRecipient(recipient, CONTACT_IDS_EDIT.key);
    if (recipErr)  { showFieldError(recipErr); return; }

    if (_editingId && _contacts[_editingId]) {
      _contacts[_editingId] = {
        ..._contacts[_editingId],
        channelId,
        username,
        ageRecipient: recipient,
      };
    }
    _editingId = null;
    const saveEditBtn = document.getElementById('btn-save-edit');
    await withSaveButton(saveEditBtn, 'Saving changes…', async () => {
      await ensureContactsKey();
      await saveContacts(_contacts);
      await bgContactsUpdated();
      await showMain();
      showToast('Changes saved');
    });
  });

  // ─── Member picker ────────────────────────────────────────────────────────────
  
  // Shared sheet used by both group and server creation/edit screens.
  // _pickerContext: { mode: 'add-group'|'edit-group'|'add-server'|'edit-server',
  //                   maxMembers: number, selectedUUIDs: Set<string> }

  let _pickerContext = null;

  function contactsForPicker() {
    return Object.values(_contacts).filter(c => c.type === 'contact' || !c.type);
  }

  function renderMemberPicker(query = '') {
    const list = document.getElementById('member-picker-list');
    list.replaceChildren();
    const q = query.trim().toLowerCase();
    const contacts = contactsForPicker().filter(c =>
      !q || c.username.toLowerCase().includes(q)
    );
    const maxMembers = _pickerContext?.maxMembers ?? Infinity;
    contacts.forEach(c => {
      const checked = _pickerContext?.selectedUUIDs.has(c.id) ?? false;
      // The checkbox is visually hidden but stays focusable; .pick-check draws the state.
      const row = document.createElement('label');
      row.className = 'pick-row row';
      row.dataset.id = c.id;
      const cb = document.createElement('input');
      cb.type    = 'checkbox';
      cb.checked = checked;
      if (!checked && _pickerContext?.selectedUUIDs.size >= maxMembers) cb.disabled = true;
      cb.addEventListener('change', () => {
        if (cb.checked) {
          if (_pickerContext.selectedUUIDs.size < maxMembers)
            _pickerContext.selectedUUIDs.add(c.id);
          else cb.checked = false;
        } else {
          _pickerContext.selectedUUIDs.delete(c.id);
        }
        renderMemberPicker(document.getElementById('member-picker-search').value);
        // The rows were rebuilt; hand keyboard focus back to the one just toggled.
        [...list.children].find(r => r.dataset.id === c.id)?.querySelector('input')?.focus();
      });
      const name = Object.assign(document.createElement('span'), { className: 'row-title', textContent: c.username });
      const main = Object.assign(document.createElement('span'), { className: 'row-main' });
      main.append(name);
      const check = document.createElement('span');
      check.className = 'pick-check';
      check.setAttribute('aria-hidden', 'true');
      check.append(icon('i-check'));
      row.append(cb, makeAvatar(c, 'avatar-sm'), main, check);
      list.appendChild(row);
    });
    if (!contacts.length) {
      const msg = document.createElement('p');
      msg.className = 'pick-empty';
      msg.textContent = q ? 'No contacts match.' : 'No contacts yet — add contacts first.';
      list.appendChild(msg);
    }
    // Only touch the live region when the text changes, so typing in search is silent.
    const countEl = document.getElementById('member-picker-count');
    const countText = `${_pickerContext?.selectedUUIDs.size ?? 0} selected`;
    if (countEl.textContent !== countText) countEl.textContent = countText;
  }

  function openMemberPicker(context) {
    _pickerContext = context;
    document.getElementById('member-picker-search').value = '';
    renderMemberPicker('');
    openDialog('sheet-member-picker');
  }

  function closeMemberPicker() {
    return closeDialog('sheet-member-picker');
  }

  document.getElementById('member-picker-search').addEventListener('input', e => {
    renderMemberPicker(e.target.value);
  });
  // Cancel discards the picker's changes; Done applies them.
  document.getElementById('btn-member-picker-cancel').addEventListener('click', closeMemberPicker);
  document.getElementById('btn-member-picker-done').addEventListener('click', async () => {
    const ctx = _pickerContext;
    // Apply the selection once the picker is gone, so the chips behind it don't
    // change while it is still sliding down.
    await closeMemberPicker();
    if (!ctx) return;
    const uuids = [...ctx.selectedUUIDs];
    applyMemberSelection(ctx.mode, uuids);
  });

  // ─── Member chip rendering (used by group/server forms) ───────────────────────

  function renderMemberChips(containerEl, countEl, uuids, maxMembers) {
    containerEl.replaceChildren();
    const displayMax = maxMembers === Infinity ? '' : ` / ${maxMembers}`;
    if (countEl) countEl.textContent = `${uuids.length}${displayMax}`;
    uuids.forEach(uuid => {
      const c = _contacts[uuid];
      if (!c) return;
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.append(makeAvatar(c), c.username);
      containerEl.appendChild(chip);
    });
  }

  function applyMemberSelection(mode, uuids) {
    // The members error is resolved once at least one member is chosen. Compare
    // the text so an unrelated form-level error (e.g. a limit) is left alone.
    const slot = $(MEMBER_ERROR_SLOT[mode]);
    if (uuids.length >= 1 && slot && slot.textContent === MEMBERS_REQUIRED_MSG) clearErr(slot);

    if (mode === 'add-group') {
      _groupAddMembers = uuids;
      renderMemberChips(
        document.getElementById('group-member-list'),
        document.getElementById('group-member-count'),
        uuids, MAX_GROUP_MEMBERS
      );
    } else if (mode === 'edit-group') {
      _groupEditMembers = uuids;
      renderMemberChips(
        document.getElementById('edit-group-member-list'),
        document.getElementById('edit-group-member-count'),
        uuids, MAX_GROUP_MEMBERS
      );
    } else if (mode === 'add-server') {
      _serverAddMembers = uuids;
      renderMemberChips(
        document.getElementById('server-member-list'),
        document.getElementById('server-member-count'),
        uuids, Infinity
      );
    } else if (mode === 'edit-server') {
      _serverEditMembers = uuids;
      renderMemberChips(
        document.getElementById('edit-server-member-list'),
        document.getElementById('edit-server-member-count'),
        uuids, Infinity
      );
    }
  }

  // ─── Group form state ─────────────────────────────────────────────────────────

  let _groupAddMembers  = [];   // UUIDs selected in the add-group form
  let _groupEditMembers = [];   // UUIDs selected in the edit-group form
  let _editingGroupId   = null; // UUID of the group being edited

  function resetGroupForm(mode) {
    if (mode === 'add') {
      _groupAddMembers = [];
      document.getElementById('group-channel-id').value = '';
      document.getElementById('group-name').value       = '';
      document.getElementById('group-member-list').replaceChildren();
      document.getElementById('group-member-count').textContent = `0 / ${MAX_GROUP_MEMBERS}`;
    } else {
      _groupEditMembers = [];
      document.getElementById('edit-group-channel-id').value = '';
      document.getElementById('edit-group-name').value       = '';
      document.getElementById('edit-group-member-list').replaceChildren();
      document.getElementById('edit-group-member-count').textContent = `0 / ${MAX_GROUP_MEMBERS}`;
      clearErr(document.getElementById('edit-group-error'));
      clearFieldErrors(EDIT_GROUP_FIELDS);
    }
  }

  document.getElementById('btn-group-pick-members').addEventListener('click', () => {
    openMemberPicker({ mode: 'add-group', maxMembers: MAX_GROUP_MEMBERS, selectedUUIDs: new Set(_groupAddMembers) });
  });

  document.getElementById('btn-back-edit-group').addEventListener('click', () => { _editingGroupId = null; showMain(); });

  document.getElementById('btn-edit-group-pick-members').addEventListener('click', () => {
    openMemberPicker({ mode: 'edit-group', maxMembers: MAX_GROUP_MEMBERS, selectedUUIDs: new Set(_groupEditMembers) });
  });

  document.getElementById('btn-save-edit-group').addEventListener('click', async () => {
    const channelId = document.getElementById('edit-group-channel-id').value.trim();
    const name      = document.getElementById('edit-group-name').value.trim();
    const errEl     = document.getElementById('edit-group-error');
    clearErr(errEl);
    clearFieldErrors(EDIT_GROUP_FIELDS);

    const groupErr = validateGroupFields(channelId, name, _editingGroupId, GROUP_IDS_EDIT);
    if (groupErr) { showFieldError(groupErr); return; }
    if (_groupEditMembers.length < 1) {
      showErr(errEl, MEMBERS_REQUIRED_MSG);
      document.getElementById('btn-edit-group-pick-members').focus();
      return;
    }

    if (_editingGroupId && _contacts[_editingGroupId]) {
      _contacts[_editingGroupId] = { ..._contacts[_editingGroupId], channelId, name, memberIds: _groupEditMembers };
    }
    _editingGroupId = null;
    const saveGroupBtn = document.getElementById('btn-save-edit-group');
    await withSaveButton(saveGroupBtn, 'Saving changes…', async () => {
      await ensureContactsKey();
      await saveContacts(_contacts);
      await bgContactsUpdated();
      await showMain();
      showToast('Changes saved');
    });
  });

  // ─── Group sheet ──────────────────────────────────────────────────────────────

  async function openGroupSheet(uuid) {
    _selectedGroupId = uuid;
    const g = _contacts[uuid];
    document.getElementById('sheet-group-name').textContent    = g.name;
    document.getElementById('sheet-group-sub').textContent     = entrySub(g);
    document.getElementById('sheet-group-channel').textContent = g.channelId;
    document.getElementById('sheet-group-toggle').checked      = g.enabled && (g.memberIds?.length > 0);
    openDialog('sheet-group');
  }

  document.getElementById('sheet-group-toggle').addEventListener('change', async e => {
    if (!_selectedGroupId) return;
    if (e.target.checked && !(_contacts[_selectedGroupId].memberIds?.length > 0)) {
      e.target.checked = false;
      _contacts[_selectedGroupId].enabled = false;
      showToast('Add a member first', true);
      return;
    }
    _contacts[_selectedGroupId].enabled = e.target.checked;
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();
  });

  document.getElementById('btn-edit-group').addEventListener('click', async () => {
    if (!_selectedGroupId) return;
    const g = _contacts[_selectedGroupId];
    _editingGroupId   = _selectedGroupId;
    _groupEditMembers = [...(g.memberIds ?? [])];
    document.getElementById('edit-group-channel-id').value = g.channelId;
    document.getElementById('edit-group-name').value       = g.name;
    clearErr(document.getElementById('edit-group-error'));
    clearFieldErrors(EDIT_GROUP_FIELDS);
    renderMemberChips(
      document.getElementById('edit-group-member-list'),
      document.getElementById('edit-group-member-count'),
      _groupEditMembers, MAX_GROUP_MEMBERS
    );
    await closeSheet();
    show('edit-group');
  });

  document.getElementById('btn-delete-group').addEventListener('click', () => {
    if (!_selectedGroupId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedGroupId].name}" group will be permanently removed.`;
    openDialog('modal-delete-contact');
  });

  document.getElementById('btn-close-group-sheet').addEventListener('click', closeSheet);

  // ─── Server form state ────────────────────────────────────────────────────────

  let _serverAddMembers  = [];
  let _serverEditMembers = [];
  let _editingServerId   = null; // UUID of the server entry being edited

  function resetServerForm(mode) {
    if (mode === 'add') {
      _serverAddMembers = [];
      document.getElementById('server-id-input').value = '';
      document.getElementById('server-name').value     = '';
      document.getElementById('server-member-list').replaceChildren();
      document.getElementById('server-member-count').textContent = '0';
    } else {
      _serverEditMembers = [];
      document.getElementById('edit-server-id-input').value = '';
      document.getElementById('edit-server-name').value     = '';
      document.getElementById('edit-server-member-list').replaceChildren();
      document.getElementById('edit-server-member-count').textContent = '0';
      clearErr(document.getElementById('edit-server-error'));
      clearFieldErrors(EDIT_SERVER_FIELDS);
    }
  }

  document.getElementById('btn-server-pick-members').addEventListener('click', () => {
    openMemberPicker({ mode: 'add-server', maxMembers: Infinity, selectedUUIDs: new Set(_serverAddMembers) });
  });

  document.getElementById('btn-back-edit-server').addEventListener('click', () => { _editingServerId = null; showMain(); });

  document.getElementById('btn-edit-server-pick-members').addEventListener('click', () => {
    openMemberPicker({ mode: 'edit-server', maxMembers: Infinity, selectedUUIDs: new Set(_serverEditMembers) });
  });

  document.getElementById('btn-save-edit-server').addEventListener('click', async () => {
    const serverId = document.getElementById('edit-server-id-input').value.trim();
    const name     = document.getElementById('edit-server-name').value.trim();
    const errEl    = document.getElementById('edit-server-error');
    clearErr(errEl);
    clearFieldErrors(EDIT_SERVER_FIELDS);

    const serverErr = validateServerFields(serverId, name, _editingServerId, SERVER_IDS_EDIT);
    if (serverErr) { showFieldError(serverErr); return; }
    if (_serverEditMembers.length < 1) {
      showErr(errEl, MEMBERS_REQUIRED_MSG);
      document.getElementById('btn-edit-server-pick-members').focus();
      return;
    }

    if (_editingServerId && _contacts[_editingServerId]) {
      _contacts[_editingServerId] = { ..._contacts[_editingServerId], serverId, name, memberIds: _serverEditMembers };
    }
    _editingServerId = null;
    const saveServerBtn = document.getElementById('btn-save-edit-server');
    await withSaveButton(saveServerBtn, 'Saving changes…', async () => {
      await ensureContactsKey();
      await saveContacts(_contacts);
      await bgContactsUpdated();
      await showMain();
      showToast('Changes saved');
    });
  });

  // ─── Server sheet ─────────────────────────────────────────────────────────────

  async function openServerSheet(uuid) {
    _selectedServerId = uuid;
    const s = _contacts[uuid];
    document.getElementById('sheet-server-name').textContent       = s.name;
    document.getElementById('sheet-server-sub').textContent        = entrySub(s);
    document.getElementById('sheet-server-id-display').textContent = s.serverId;
    document.getElementById('sheet-server-toggle').checked         = s.enabled && (s.memberIds?.length > 0);
    openDialog('sheet-server');
  }

  document.getElementById('sheet-server-toggle').addEventListener('change', async e => {
    if (!_selectedServerId) return;
    if (e.target.checked && !(_contacts[_selectedServerId].memberIds?.length > 0)) {
      e.target.checked = false;
      _contacts[_selectedServerId].enabled = false;
      showToast('Add a member first', true);
      return;
    }
    _contacts[_selectedServerId].enabled = e.target.checked;
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();
  });

  document.getElementById('btn-edit-server').addEventListener('click', async () => {
    if (!_selectedServerId) return;
    const s = _contacts[_selectedServerId];
    _editingServerId   = _selectedServerId;
    _serverEditMembers = [...(s.memberIds ?? [])];
    document.getElementById('edit-server-id-input').value = s.serverId;
    document.getElementById('edit-server-name').value     = s.name;
    clearErr(document.getElementById('edit-server-error'));
    clearFieldErrors(EDIT_SERVER_FIELDS);
    renderMemberChips(
      document.getElementById('edit-server-member-list'),
      document.getElementById('edit-server-member-count'),
      _serverEditMembers, Infinity
    );
    await closeSheet();
    show('edit-server');
  });

  document.getElementById('btn-delete-server').addEventListener('click', () => {
    if (!_selectedServerId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedServerId].name}" server will be permanently removed.`;
    openDialog('modal-delete-contact');
  });

  document.getElementById('btn-close-server-sheet').addEventListener('click', closeSheet);

  // ─── Export contacts ──────────────────────────────────────────────────────────

  document.getElementById('btn-export-contacts').addEventListener('click', () => {
    const entries = Object.values(_contacts).map(c => {
      if (c.type === 'group')
        return { id: c.id, type: 'group', enabled: c.enabled, channelId: c.channelId, name: c.name, memberIds: c.memberIds ?? [] };
      if (c.type === 'server')
        return { id: c.id, type: 'server', enabled: c.enabled, serverId: c.serverId, name: c.name, memberIds: c.memberIds ?? [] };
      return { id: c.id, type: 'contact', enabled: c.enabled, channelId: c.channelId, username: c.username, ageRecipient: c.ageRecipient };
    });

    const json = JSON.stringify({ version: CONTACTS_VERSION, entries }, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);

    // toISOString() always produces YYYY-MM-DD regardless of locale/OS settings,
    // giving a consistent, sortable filename across all environments.
    const datePart = new Date().toISOString().slice(0, 10);

    const a = Object.assign(document.createElement('a'), {
      href:     url,
      download: `agecord_${datePart}.json`,
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('Contacts exported');
  });

  // ─── Import contacts ──────────────────────────────────────────────────────────

  // One result alert for every outcome: lit check on success, danger seal on failure.
  function showImportResult(ok, message) {
    $('modal-import-contacts-title').textContent = ok ? 'Import complete' : 'Import failed';
    $('modal-import-contacts-msg').textContent   = message;
    $('import-result-seal').classList.toggle('is-lit', ok);
    $('import-result-seal').classList.toggle('is-danger', !ok);
    openDialog('modal-import-contacts');
  }

  async function doImportContacts(json) {
    // Reject oversized files before JSON.parse to prevent freezing the UI thread.
    if (json.length > IMPORT_SIZE_LIMIT) {
      showImportResult(false, `File too large — contacts exports must be under ${(IMPORT_SIZE_LIMIT / 1024 / 1024).toFixed(1)} MiB.`);
      return;
    }

    let parsed;
    try { parsed = JSON.parse(json); }
    catch {
      showImportResult(false, 'Could not parse file — make sure it is a valid contacts export.');
      return;
    }

    // Reject v1 outright (version !== 2, or bare array without version field).
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.version !== CONTACTS_VERSION) {
      showImportResult(false, 'Unsupported format — only v2 exports (version: 2) are accepted. v1 imports are no longer supported.');
      return;
    }

    const entries = parsed.entries;
    if (!Array.isArray(entries)) {
      showImportResult(false, 'Unrecognised format — expected a v2 contacts export JSON with an "entries" array.');
      return;
    }

    // ── Pass 1: collect file UUIDs for memberIds cross-reference ─────────────────
    
    const fileUUIDs = new Set(entries.map(e => e?.id).filter(Boolean));

    // ── Pass 2: detect intra-file duplicate UUIDs ─────────────────────────────────
    
    const seenUUIDs      = new Map();
    const dupUUIDIndices = new Set();
    entries.forEach((entry, idx) => {
      const id = entry?.id;
      if (!id) return;
      if (seenUUIDs.has(id)) { dupUUIDIndices.add(idx); dupUUIDIndices.add(seenUUIDs.get(id)); }
      else seenUUIDs.set(id, idx);
    });

    // ── Pass 3: detect intra-file duplicate channelIds / serverIds ────────────────
    
    const fileChannelIds  = new Map();
    const fileServerIds   = new Map();
    const dupFieldIndices = new Set();
    entries.forEach((entry, idx) => {
      if (!entry) return;
      if (entry.channelId) {
        if (fileChannelIds.has(entry.channelId)) { dupFieldIndices.add(idx); dupFieldIndices.add(fileChannelIds.get(entry.channelId)); }
        else fileChannelIds.set(entry.channelId, idx);
      }
      if (entry.serverId) {
        if (fileServerIds.has(entry.serverId)) { dupFieldIndices.add(idx); dupFieldIndices.add(fileServerIds.get(entry.serverId)); }
        else fileServerIds.set(entry.serverId, idx);
      }
    });

    const existingChannelIds   = contactsByChannelId(_contacts);
    const existingServerIds    = new Map(Object.values(_contacts).filter(c => c.type === 'server' && c.serverId).map(c => [c.serverId, c]));
    const existingContactCount = Object.values(_contacts).filter(c => c.type === 'contact' || !c.type).length;
    const existingServerCount  = Object.values(_contacts).filter(c => c.type === 'server').length;

    let contactsAdded = 0;
    let serversAdded  = 0, groupsAdded = 0;
    let skipped = 0, limitSkipped = 0;

    for (let idx = 0; idx < entries.length; idx++) {
      const entry = entries[idx] ?? {};

      if (typeof entry.id !== 'string' || !entry.id)                   { skipped++; continue; }
      if (dupUUIDIndices.has(idx))                                      { skipped++; continue; }
      if (dupFieldIndices.has(idx))                                     { skipped++; continue; }

      const type = entry.type ?? 'contact';

      // ── Contact ──────────────────────────────────────────────────────────────
      if (type === 'contact') {
        const { id, channelId, username, ageRecipient, enabled } = entry;

        if (!channelId || !username || !ageRecipient)                   { skipped++; continue; }
        if (!/^\d+$/.test(channelId) || channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID) { skipped++; continue; }
        if (typeof username !== 'string' || username.length < MIN_USERNAME || username.length > MAX_USERNAME)    { skipped++; continue; }
        if (!isPrintableAscii(username))                                                                          { skipped++; continue; }
        if (typeof ageRecipient !== 'string' || !ageRecipient.startsWith('age1pq1') || !/;mldsa87:[A-Za-z0-9+/]+=*$/.test(ageRecipient)) { skipped++; continue; }
        if (Object.prototype.hasOwnProperty.call(_contacts, id))        { skipped++; continue; }

        const existingForChannel = existingChannelIds.get(channelId);
        if (existingForChannel && existingForChannel.id !== id)         { skipped++; continue; }
        if (existingContactCount + contactsAdded >= MAX_CONTACTS)       { limitSkipped++; continue; }

        _contacts[id] = { id, type: 'contact', channelId, username, ageRecipient, enabled: enabled !== false };
        existingChannelIds.set(channelId, _contacts[id]);
        contactsAdded++;

      // ── Group ────────────────────────────────────────────────────────────────
      
      } else if (type === 'group') {
        const { id, channelId, name, memberIds, enabled } = entry;

        if (!channelId || !name)                                        { skipped++; continue; }
        if (!/^\d+$/.test(channelId) || channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID) { skipped++; continue; }
        if (typeof name !== 'string' || name.length < MIN_USERNAME || name.length > MAX_USERNAME) { skipped++; continue; }
        if (!isPrintableAscii(name))                                                               { skipped++; continue; }
        if (!Array.isArray(memberIds))                                  { skipped++; continue; }
        if (Object.prototype.hasOwnProperty.call(_contacts, id))        { skipped++; continue; }

        const existingForChannel = existingChannelIds.get(channelId);
        if (existingForChannel && existingForChannel.id !== id)         { skipped++; continue; }

        // memberIds must all exist in the same file; cross-extension refs are not accepted.
        const validMembers = memberIds.filter(mid => fileUUIDs.has(mid));
        if (validMembers.length !== memberIds.length)                   { skipped++; continue; }

        _contacts[id] = { id, type: 'group', channelId, name, memberIds: validMembers, enabled: enabled !== false };
        existingChannelIds.set(channelId, _contacts[id]);
        groupsAdded++;

      // ── Server ───────────────────────────────────────────────────────────────
      
      } else if (type === 'server') {
        const { id, serverId, name, memberIds, enabled } = entry;

        if (!serverId || !name)                                         { skipped++; continue; }
        if (!/^\d{1,20}$/.test(serverId))                               { skipped++; continue; }
        if (typeof name !== 'string' || name.length < MIN_USERNAME || name.length > MAX_USERNAME) { skipped++; continue; }
        if (!isPrintableAscii(name))                                                               { skipped++; continue; }
        if (!Array.isArray(memberIds))                                  { skipped++; continue; }
        if (Object.prototype.hasOwnProperty.call(_contacts, id))        { skipped++; continue; }
        if (existingServerIds.has(serverId))                            { skipped++; continue; }
        if (existingServerCount + serversAdded >= MAX_SERVERS)          { limitSkipped++; continue; }

        const validMembers = memberIds.filter(mid => fileUUIDs.has(mid));
        if (validMembers.length !== memberIds.length)                   { skipped++; continue; }

        _contacts[id] = { id, type: 'server', serverId, name, memberIds: validMembers, enabled: enabled !== false };
        existingServerIds.set(serverId, _contacts[id]);
        serversAdded++;

      } else {
        skipped++;
      }
    }

    await ensureContactsKey();
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();

    const parts = [];
    if (contactsAdded)  parts.push(`${contactsAdded} contact${contactsAdded !== 1 ? 's' : ''} added`);
    if (groupsAdded)    parts.push(`${groupsAdded} group${groupsAdded !== 1 ? 's' : ''} added`);
    if (serversAdded)   parts.push(`${serversAdded} server${serversAdded !== 1 ? 's' : ''} added`);
    if (skipped)        parts.push(`${skipped} skipped (invalid or duplicate)`);
    if (limitSkipped)   parts.push(`${limitSkipped} skipped (limit reached)`);
    showImportResult(true, (parts.join(', ') || 'Nothing changed') + '.');
  }

  document.getElementById('btn-import-contacts').addEventListener('click', () => {
    browser.tabs.create({ url: browser.runtime.getURL('popup/import-helper.html') });
  });

  let _importHelperTabId = null;

  function closeImportHelperTab() {
    if (_importHelperTabId === null) return;
    const id = _importHelperTabId;
    _importHelperTabId = null;
    browser.tabs.remove(id).catch(() => {});
  }

  async function checkPendingImport() {
    try {
      const data = await browser.storage.session.get(['pending_import', 'pending_import_tab']);
      if (!data.pending_import) return;
      // If the vault is locked at this point, the user must have manually locked it
      if (document.getElementById('screen-lock').hidden === false) {
        await browser.storage.session.remove(['pending_import', 'pending_import_tab']);
        if (data.pending_import_tab != null)
          browser.tabs.remove(data.pending_import_tab).catch(() => {});
        return;
      }
      // Wait for showMain() contact load to finish before import.
      // Prevents loadContacts() reassignment from overwriting import changes.
      // Ensures mutation targets the final _contacts state.
      if (_mainReadyPromise) {
        await _mainReadyPromise.catch(() => {});
        _mainReadyPromise = null;
      }
      _importHelperTabId = data.pending_import_tab ?? null;
      await browser.storage.session.remove(['pending_import', 'pending_import_tab']);
      await doImportContacts(data.pending_import);
    } catch {}
  }

  document.getElementById('btn-import-contacts-ok').addEventListener('click', () => {
    closeDialog('modal-import-contacts');
    closeImportHelperTab();
  });

  window.addEventListener('unload', () => {
    if (document.getElementById('modal-import-contacts').open) {
      closeImportHelperTab();
    }
  });

  // ─── My key screen ────────────────────────────────────────────────────────────

  document.getElementById('btn-back-key').addEventListener('click', showMain);

  async function showMyKey() {
    const ageRecipient = await getAgeRecipient();
    if (!ageRecipient) return;
    document.getElementById('my-key-box').textContent = ageRecipient;
    renderFingerprint(document.getElementById('my-key-fp'), 'Computing fingerprint…');
    show('my-key');
    renderFingerprint(document.getElementById('my-key-fp'), await keyFingerprint(ageRecipient));
  }

  document.getElementById('btn-copy-key').addEventListener('click', async () => {
    const ageRecipient = await getAgeRecipient();
    if (!ageRecipient) return;
    await navigator.clipboard.writeText(ageRecipient);
    const btn   = document.getElementById('btn-copy-key');
    const label = document.getElementById('btn-copy-key-label');
    btn.classList.add('copied');
    label.textContent = 'Copied';
    announce('Public key copied');
    setTimeout(() => {
      btn.classList.remove('copied');
      label.textContent = 'Copy';
    }, 1600);
  });

  // ─── Export private key ───────────────────────────────────────────────────────

  // Preserve export passphrases across accidental popup dismissal via a TTL draft.
  const EXPORT_DRAFT_FIELDS = ['export-passphrase-input', 'export-new-passphrase', 'export-new-passphrase2'];
  const { save: saveExportDraft, restore: restoreExportDraft, clear: clearExportDraft } =
    makeDraftManager('export_draft', EXPORT_DRAFT_FIELDS);
  EXPORT_DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveExportDraft));

  function wipeExportModal() {
    document.getElementById('export-passphrase-input').value  = '';
    document.getElementById('export-new-passphrase').value    = '';
    document.getElementById('export-new-passphrase2').value   = '';
    clearErr(document.getElementById('export-passphrase-error'));
    clearFieldErrors(EXPORT_FIELDS);
    document.getElementById('export-spinner').hidden          = true;
    setStatus('export-status', '');
    document.getElementById('btn-export-confirm').disabled    = false;
    document.getElementById('btn-export-confirm').textContent = 'Encrypt & show';
  }
  // Closing wipes the form only after the exit animation, so fields don't empty
  // (and the button label flip) while the sheet is still sliding away.
  function resetExportModal() {
    afterDialogClosed('modal-export-key', wipeExportModal);
  }

  document.getElementById('btn-export-key').addEventListener('click', async () => {
    wipeExportModal();
    await restoreExportDraft();
    openDialog('modal-export-key');
  });

  document.getElementById('btn-export-cancel').addEventListener('click', () => {
    // Explicit cancel — the typed passphrases no longer serve any purpose.
    resetExportModal();
    clearExportDraft();
  });

  document.getElementById('form-export').addEventListener('submit', async e => {
    e.preventDefault();
    const unlockPass  = document.getElementById('export-passphrase-input').value;
    const exportPass  = document.getElementById('export-new-passphrase').value;
    const exportPass2 = document.getElementById('export-new-passphrase2').value;
    const errEl       = document.getElementById('export-passphrase-error');
    const btn         = document.getElementById('btn-export-confirm');
    const spinner     = document.getElementById('export-spinner');

    clearErr(errEl);
    clearFieldErrors(EXPORT_FIELDS);
    if (!unlockPass) {
      showFieldError({ fieldId: 'export-passphrase-input', message: 'Enter your unlock passphrase.' });
      return;
    }

    // The message is read as the description of the "Export passphrase" field,
    // so it no longer needs an "Export passphrase:" prefix.
    const exportPassErr = validatePassphrase(exportPass, 'export-new-passphrase');
    if (exportPassErr)              { showFieldError(exportPassErr); return; }
    if (exportPass !== exportPass2) {
      document.getElementById('export-new-passphrase').value  = '';
      document.getElementById('export-new-passphrase2').value = '';
      saveExportDraft();
      // Only the confirmation field is wrong.
      showFieldError({ fieldId: 'export-new-passphrase2', message: 'Export passphrases do not match.' });
      return;
    }

    btn.disabled    = true;
    btn.textContent = 'Verifying…';
    spinner.hidden  = false;
    setStatus('export-status', 'Encrypting... do not close this window.');

    try {
      const identity = await loadAndDecryptIdentity(unlockPass, 'Wrong unlock passphrase.');

      btn.textContent = 'Encrypting…';
      const envelopeB64 = await encryptIdentityBlob(identity, exportPass);

      resetExportModal();
      clearExportDraft();
      document.getElementById('export-key-blob').value = envelopeB64;
      openDialog('modal-export-display');

    } catch (e) {
      // Re-enable the controls before focusing a field below.
      btn.disabled    = false;
      btn.textContent = 'Encrypt & show';
      spinner.hidden  = true;
      setStatus('export-status', '');
      if (e.message === 'Wrong unlock passphrase.') {
        // Confirmed wrong — only this field is invalid, leave the export
        // passphrase pair (which the user may have gotten right) alone.
        document.getElementById('export-passphrase-input').value = '';
        saveExportDraft();
        showFieldError({ fieldId: 'export-passphrase-input', message: e.message });
      } else {
        showErr(errEl, e.message === 'OUTDATED_FORMAT'
          ? 'Your identity format is outdated. Please regenerate your key.'
          : 'Export failed: ' + e.message
        );
      }
    }
  });

  function closeExportDisplay() {
    // Clear the key text once the sheet has left rather than blanking it mid-slide.
    afterDialogClosed('modal-export-display', () => {
      document.getElementById('export-key-blob').value = '';
    });
  }
  document.getElementById('btn-export-copy').addEventListener('click', async () => {
    const blob = document.getElementById('export-key-blob').value;
    let copied = false;
    try { await navigator.clipboard.writeText(blob); copied = true; } catch { }
    closeExportDisplay();
    if (copied) showToast('Copied to clipboard');
  });
  document.getElementById('btn-export-close').addEventListener('click', closeExportDisplay);
  document.getElementById('btn-export-close-x').addEventListener('click', closeExportDisplay);

  // ─── Keypair regeneration ─────────────────────────────────────────────────────

  async function regenerateKeypair() {
    Object.values(_contacts).forEach(c => { c.enabled = false; });
    // Contacts are intentionally discarded on keypair regeneration — the new
    // identity is a new encryption context and all prior public keys are stale.
    await store.remove(['ageRecipient', 'identity_blob', 'ageEncryptedIdentity',
                        'contactsSaltB64', 'contactsEnc', 'format_version']);
    await clearSession();
    _sessionIdentity   = null;
    _sessionPassphrase = null;
    await bgSend({ type: 'RELOCK' });
    await bgSend({ type: 'RELOAD_DISCORD_TABS' });
    document.getElementById('setup-passphrase').value  = '';
    document.getElementById('setup-passphrase2').value = '';
    clearErr(document.getElementById('setup-error'));
    clearFieldErrors(SETUP_FIELDS);
    updateStrength();
    show('setup', 'back');
    showToast('Keypair regenerated');
  }

  wireConfirmModal({
    openBtn:    'btn-regen',
    cancelBtn:  'btn-regen-cancel',
    confirmBtn: 'btn-regen-confirm',
    modal:      'modal-regen',
    input:      'regen-confirm-input',
    onConfirm:  regenerateKeypair,
  });

  // ─── Clear all data (from My Key screen) ─────────────────────────────────────

  wireConfirmModal({
    openBtn:    'btn-clear-data',
    cancelBtn:  'btn-clear-data-cancel',
    confirmBtn: 'btn-clear-data-confirm',
    modal:      'modal-clear-data',
    input:      'clear-data-confirm-input',
    onConfirm:  () => resetToSetupScreen(),
  });

  // ─── Change passphrase ────────────────────────────────────────────────────────

  function wipeChangePassModal() {
    document.getElementById('change-pass-current').value  = '';
    document.getElementById('change-pass-new').value      = '';
    document.getElementById('change-pass-new2').value     = '';
    clearErr(document.getElementById('change-pass-error'));
    clearFieldErrors(CHANGE_PASS_FIELDS);
    document.getElementById('change-pass-spinner').hidden = true;
    setStatus('change-pass-status', '');
    const btn = document.getElementById('btn-change-pass-confirm');
    btn.disabled    = false;
    btn.textContent = 'Change passphrase';
  }
  function resetChangePassModal() {
    afterDialogClosed('modal-change-passphrase', wipeChangePassModal);
  }

  document.getElementById('btn-change-passphrase').addEventListener('click', () => {
    wipeChangePassModal();
    openDialog('modal-change-passphrase');
  });

  document.getElementById('btn-change-pass-cancel').addEventListener('click', resetChangePassModal);

  document.getElementById('form-change-pass').addEventListener('submit', async e => {
    e.preventDefault();
    const currentPass = document.getElementById('change-pass-current').value;
    const newPass     = document.getElementById('change-pass-new').value;
    const newPass2    = document.getElementById('change-pass-new2').value;
    const errEl       = document.getElementById('change-pass-error');
    const btn         = document.getElementById('btn-change-pass-confirm');
    const spinner     = document.getElementById('change-pass-spinner');
    clearErr(errEl);
    clearFieldErrors(CHANGE_PASS_FIELDS);

    if (!currentPass) {
      showFieldError({ fieldId: 'change-pass-current', message: 'Enter your current passphrase.' });
      return;
    }
    const newPassErr = validatePassphrase(newPass, 'change-pass-new');
    if (newPassErr)              { showFieldError(newPassErr); return; }
    if (newPass !== newPass2) {
      document.getElementById('change-pass-new').value  = '';
      document.getElementById('change-pass-new2').value = '';
      // Only the confirmation field is wrong.
      showFieldError({ fieldId: 'change-pass-new2', message: 'New passphrases do not match.' });
      return;
    }
    if (newPass === currentPass) {
      showFieldError({ fieldId: 'change-pass-new', message: 'New passphrase must differ from current.' });
      return;
    }

    btn.disabled    = true;
    btn.textContent = 'Verifying…';
    spinner.hidden  = false;
    setStatus('change-pass-status', 'Re-encrypting... do not close this window.');

    try {
      const identity = await loadAndDecryptIdentity(currentPass, 'Wrong current passphrase.');

      btn.textContent = 'Re-encrypting…';
      const envelopeB64 = await encryptIdentityBlob(identity, newPass);
      await store.set({ identity_blob: envelopeB64, format_version: 2 });

      // Update cached passphrase and re-derive the contacts key under the new
      // passphrase with a fresh salt so old ciphertext is invalidated.
      _sessionPassphrase = newPass;
      await setSessionPassphrase(newPass);
      await store.remove(['contactsSaltB64', 'contactsEnc']);
      await bgUnlock(identity, newPass);
      await saveContacts(_contacts);

      resetChangePassModal();
      showToast('Passphrase changed');

    } catch (e) {
      // Re-enable the controls before focusing a field below.
      btn.disabled    = false;
      btn.textContent = 'Change passphrase';
      spinner.hidden  = true;
      setStatus('change-pass-status', '');
      if (e.message === 'Wrong current passphrase.') {
        document.getElementById('change-pass-current').value = '';
        showFieldError({ fieldId: 'change-pass-current', message: e.message });
      } else {
        showErr(errEl, e.message === 'OUTDATED_FORMAT'
          ? 'Your identity format is outdated. Please regenerate your key.'
          : 'Change failed: ' + e.message
        );
      }
    }
  });

  // ─── Utilities ────────────────────────────────────────────────────────────────

  async function loadAndDecryptIdentity(passphrase, wrongPassErr) {
    const stored = await store.get(['identity_blob', 'ageEncryptedIdentity']);
    const blobB64 = stored.identity_blob || stored.ageEncryptedIdentity;
    if (!blobB64) throw new Error('No keypair found.');
    if (!stored.identity_blob && stored.ageEncryptedIdentity)
      throw new Error('OUTDATED_FORMAT');
    try {
      return await decryptIdentityBlob(blobB64, passphrase);
    } catch (e) {
      if (e.message === 'OUTDATED_FORMAT') throw e;
      throw new Error(wrongPassErr);
    }
  }

  // ─── Base64 helpers ───────────────────────────────────────────────────────────
  const toB64   = bytes => bytes.toBase64();
  const fromB64 = b64   => Uint8Array.fromBase64(b64);

  async function keyFingerprint(recipient) {
    if (!recipient) return '(no key)';
    try {
      const bytes = shake256(new TextEncoder().encode(recipient), 64);
      let hex = '';
      for (const b of bytes) hex += b.toString(16).padStart(2, '0');
      return hex.toUpperCase().match(/.{4}/g).join(' ');
    } catch {
      return recipient.slice(0, 16) + '…' + recipient.slice(-12);
    }
  }

  // ─── About screen ────────────────────────────────────────────────────────────

  document.getElementById('btn-back-about').addEventListener('click', showMain);

  const _aboutLinks = {
    'about-repo-link':    'https://github.com/SenseiDeElite/agecord',
    'about-license-link': 'https://github.com/SenseiDeElite/agecord/blob/main/LICENSE',
  };
  Object.entries(_aboutLinks).forEach(([id, url]) => {
    document.getElementById(id).addEventListener('click', () => { browser.tabs.create({ url }); });
  });

  document.getElementById('about-notices-link').addEventListener('click', () => {
    browser.tabs.create({ url: browser.runtime.getURL('licenses.html') });
  });

  function showAbout() {
    const ver = browser.runtime.getManifest().version;
    document.getElementById('about-version').textContent = 'v' + ver;
    show('about');
  }

  // ─── Sensitive-field auto-clear ──────────────────────────────────────────────

  // Backstop: clear inactive sensitive fields after SENSITIVE_FIELD_TTL.
  const SENSITIVE_FIELD_TTL = 5 * 60 * 1000; // 5 minutes
  const SENSITIVE_FIELD_IDS = [
    'passphrase-input',
    'setup-passphrase', 'setup-passphrase2',
    'import-export-passphrase', 'import-passphrase', 'import-passphrase2',
    'export-passphrase-input', 'export-new-passphrase', 'export-new-passphrase2',
    'change-pass-current', 'change-pass-new', 'change-pass-new2',
  ];

  (function armSensitiveFieldAutoClear() {
    const timers = new Map();
    SENSITIVE_FIELD_IDS.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('input', () => {
        clearTimeout(timers.get(id));
        if (!el.value) return;
        timers.set(id, setTimeout(() => { el.value = ''; }, SENSITIVE_FIELD_TTL));
      });
    });
  })();

  // ─── Boot ────────────────────────────────────────────────────────────────────

  async function bootWithDraftCheck() {
    await boot();
    // Always check — boot() may have landed on the lock screen if the vault
    // wasn't unlocked when import-helper reopened the popup.
    await checkPendingImport();
  }

  bootWithDraftCheck().catch(e => console.error('[age] popup boot error:', e));

})();
