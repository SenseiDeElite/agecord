// popup.js — Discord Age Encryption
//
// Key storage : identity blob encrypted with Argon2id + XChaCha20-Poly1305,
//               stored as base64 in chrome.storage.local (key: identity_blob).
// Session     : decrypted identity kept in chrome.storage.session;
//               background service worker holds it in memory and sends only the
//               ML-DSA-87 signing key to content scripts.
// Crypto      : offloaded to popup/crypto-worker.js so the UI stays responsive.
// Contacts    : Argon2id key derived in crypto-worker.js, sent to background as
//               raw bytes; contacts ciphertext uses XChaCha20-Poly1305 envelope.
//
// Data model  : contacts stored as { [uuid]: ContactEntry } where uuid is a
//               stable v4 UUID generated at creation time.  channelId is a
//               field on the entry, not the map key.  This is the v2 model
//               introduced in 0.4.0.

'use strict';

(() => {

  // age-encryption and rustcrypto-wasm named imports — resolved via dynamic import().
  let Encrypter, generateHybridIdentity, identityToRecipient;
  let ml_dsa87_keygen, ml_dsa87_verifying_key_from_seed, shake256;
  const cryptoReady = Promise.all([
    import(chrome.runtime.getURL('lib/age.min.js')).then(m => {
      Encrypter              = m.Encrypter;
      generateHybridIdentity = m.generateHybridIdentity;
      identityToRecipient    = m.identityToRecipient;
    }),
    import(chrome.runtime.getURL('lib/rustcrypto-wasm.min.js')).then(async m => {
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
  const IMPORT_SIZE_LIMIT  = 1_048_576; // 1 MiB — well above the ~420 KB worst-case maximum

  // ─── Storage helpers ────────────────────────────────────────────────────────
  const store = {
    get:    keys => chrome.storage.local.get(keys),
    set:    data => chrome.storage.local.set(data),
    remove: keys => chrome.storage.local.remove(keys),
  };

  async function getAgeRecipient() {
    const d = await store.get(['ageRecipient']);
    return d.ageRecipient ?? null;
  }

  // ─── Encrypted contacts storage ──────────────────────────────────────────────
  // Contacts are stored encrypted at rest in chrome.storage.local as "contactsEnc".
  // The XChaCha20-Poly1305 key (derived via Argon2id) lives only in the background
  // service worker (_contactsKeyBytes).  The popup reads/writes contacts by sending
  // ENCRYPT_CONTACTS / DECRYPT_CONTACTS messages to the background.
  //
  // While unlocked, _contacts is the live in-memory object and is the source of
  // truth.  Any write goes: mutate _contacts → saveContacts() → store.set.
  //
  // _sessionPassphrase: held in popup memory for the lifetime of an unlocked
  //   session so that UNLOCK messages re-sent to the background (e.g. after a
  //   service-worker restart) can re-derive the contacts key without re-prompting
  //   the user.

  let _sessionPassphrase = null;

  async function saveContacts(contacts) {
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

    const resp = await bgSend({ type: 'DECRYPT_CONTACTS', ciphertextB64: contactsEnc });
    if (resp?.ok) {
      try {
        const parsed = JSON.parse(resp.json);
        await setSessionContacts(parsed);
        return parsed;
      } catch { return {}; }
    }

    // Background key unavailable (service-worker restarted, passphrase not cached).
    // Try to re-derive the key using the cached passphrase.
    if (_sessionPassphrase) {
      const identity = await getSessionIdentity();
      if (identity) {
        await bgUnlock(identity, _sessionPassphrase);
        const resp2 = await bgSend({ type: 'DECRYPT_CONTACTS', ciphertextB64: contactsEnc });
        if (resp2?.ok) {
          try {
            const parsed = JSON.parse(resp2.json);
            await setSessionContacts(parsed);
            return parsed;
          } catch { return {}; }
        }
      }
    }

    // Passphrase not available (popup was closed and reopened without re-locking).
    // Fall back to the decrypted contacts already in session storage — they were
    // written there when the contacts were last successfully loaded or saved, and
    // session storage has the same lifetime as the unlock session.
    try {
      const s = await chrome.storage.session.get('age_contacts');
      if (s.age_contacts && typeof s.age_contacts === 'object') {
        return s.age_contacts;
      }
    } catch {}

    console.error('[age] loadContacts: background decrypt failed and no session fallback:', resp?.error);
    return {};
  }

  // ─── Background messaging ────────────────────────────────────────────────────
  // All tab-relay operations go through the background service worker.

  function bgSend(msg) {
    // chrome.runtime.sendMessage returns a Promise natively in MV3.
    // Swallow lastError (no listener on the other end during early boot) so the
    // promise rejects cleanly rather than throwing an uncaught extension error.
    return chrome.runtime.sendMessage(msg).catch(e => {
      void e; // lastError consumed — callers already handle null/undefined responses
      return undefined;
    });
  }

  // Relay helpers: always bundle contacts + ageRecipient so content scripts
  // receive them without needing access to chrome.storage.session.
  // bgUnlock: full unlock — derives the Argon2id contacts key from passphrase
  // and sends it to the background along with the identity and contacts.
  // Used on first unlock, keygen, import, and passphrase change.
  async function bgUnlock(identity, passphrase) {
    const ageRecipient = await getAgeRecipient();
    let contactsKeyB64 = null;
    if (passphrase) {
      try {
        const { contactsSaltB64 } = await store.get(['contactsSaltB64']);
        const { keyB64 } = await deriveContactsKey(passphrase, contactsSaltB64 ?? null);
        contactsKeyB64 = keyB64;
      } catch (e) {
        console.warn('[age] bgUnlock: could not derive contacts key:', e?.message);
      }
    }
    return bgSend({ type: 'UNLOCK', identity, contactsKeyB64, contacts: _contacts, ageRecipient });
  }

  // bgUnlockResume: reopen path — resyncs identity + contacts with the background
  // without any key derivation.  The contacts key is derived lazily on first save
  // via ensureContactsKey(), so popup reopen is always instant.
  //
  // Optimization: if the background still holds a live identity, the service
  // worker never slept and all content scripts are already unlocked.  Skip the
  // UNLOCK broadcast entirely — it would trigger scanExisting() in every Discord
  // tab and re-render already-decrypted messages for no reason.
  // Only send UNLOCK when the background has lost its state (SW restart).
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
  // ─── Screen router ──────────────────────────────────────────────────────────
  const screens = ['lock', 'setup', 'import', 'main', 'add-contact', 'edit-contact',
                   'edit-group', 'edit-server', 'my-key', 'about'];
  const UPDATE_BTN_SCREENS = new Set(['lock', 'main']);
  const show = screenId => {
    screens.forEach(id => { document.getElementById(`screen-${id}`).hidden = (id !== screenId); });
    const btnUpdate = document.getElementById('btn-update');
    if (btnUpdate && !btnUpdate.hidden) {
      btnUpdate.style.display = UPDATE_BTN_SCREENS.has(screenId) ? '' : 'none';
    }
  };

  // ─── Session helpers ─────────────────────────────────────────────────────────

  async function getSessionIdentity() {
    try {
      const r = await chrome.storage.session.get(['age_unlocked', 'age_identity']);
      return r.age_unlocked === true ? (r.age_identity ?? null) : null;
    } catch {}
    return null;
  }

  async function setSession(identity) {
    try {
      await chrome.storage.session.set({ age_unlocked: true, age_identity: identity });
    } catch {}
  }

  // Persisted so the background can recover after a SW restart without waiting for UNLOCK.
  async function setSessionRecipient(recipient) {
    try {
      if (recipient) await chrome.storage.session.set({ age_recipient: recipient });
    } catch {}
  }

  // Persisted so the background can recover contacts after a SW restart without waiting for UNLOCK.
  async function setSessionContacts(contacts) {
    try {
      await chrome.storage.session.set({ age_contacts: contacts });
    } catch {}
  }

  async function clearSession() {
    try {
      await chrome.storage.session.remove(
        ['age_unlocked', 'age_identity', 'age_contacts', 'age_recipient',
         'age_passphrase', 'pending_unlock']);
    } catch {}
  }

  // Cached so saveContacts/loadContacts can re-derive the contacts key after a SW restart.
  async function setSessionPassphrase(passphrase) {
    try {
      if (passphrase) await chrome.storage.session.set({ age_passphrase: passphrase });
    } catch {}
  }

  async function getSessionPassphrase() {
    try {
      const r = await chrome.storage.session.get('age_passphrase');
      return r.age_passphrase ?? null;
    } catch {}
    return null;
  }

  // Marks that an unlock is in progress so boot() can detect a mid-unlock
  // dismissal and show a clean lock screen rather than the broken half-unlocked
  // state that would result from the racing doUnlock() completing in a closed
  // popup document.
  async function setPendingUnlock(val) {
    try {
      await (val
        ? chrome.storage.session.set({ pending_unlock: true })
        : chrome.storage.session.remove('pending_unlock'));
    } catch {}
  }

  // ─── Crypto worker ───────────────────────────────────────────────────────────
  // Spawns a fresh dedicated worker per call, terminated on completion.

  function runCryptoWorker(msg) {
    return new Promise((resolve, reject) => {
      const workerUrl = chrome.runtime.getURL('popup/crypto-worker.js');
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
      worker.postMessage(msg);
    });
  }

  // Salt length mirrors crypto-worker.js ARGON2ID_DERIVE expectations.
  const CONTACTS_SALT_LEN = 16;

  // Returns { keyB64, saltB64 }. Generates and persists a fresh salt if none provided.
  async function deriveContactsKey(passphrase, saltB64Opt) {
    let saltB64 = saltB64Opt;
    if (!saltB64) {
      // Generate a fresh salt and persist it.
      const salt = crypto.getRandomValues(new Uint8Array(CONTACTS_SALT_LEN));
      saltB64 = toB64(salt);
      await store.set({ contactsSaltB64: saltB64 });
    }
    const { keyB64 } = await runCryptoWorker({ op: 'ARGON2ID_DERIVE', password: passphrase, saltB64 });
    return { keyB64, saltB64 };
  }

  // Returns base64-encoded version-0x01 envelope (Argon2id + XChaCha20-Poly1305).
  async function encryptIdentityBlob(identityBlob, passphrase) {
    // Derive a fresh 32-byte key using a new random salt.
    const salt    = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = toB64(salt);

    const { keyB64 } = await runCryptoWorker({ op: 'ARGON2ID_DERIVE', password: passphrase, saltB64 });

    const plaintextB64 = toB64(new TextEncoder().encode(identityBlob));

    const { envelopeB64 } = await runCryptoWorker({
      op: 'XCHACHA_ENCRYPT', keyB64, plaintextB64, saltB64,
    });
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
    const saltB64   = toB64(saltBytes);

    const { keyB64 }       = await runCryptoWorker({ op: 'ARGON2ID_DERIVE', password: passphrase, saltB64 });
    const { plaintextB64 } = await runCryptoWorker({ op: 'XCHACHA_DECRYPT', keyB64, envelopeB64 });

    return new TextDecoder().decode(fromB64(plaintextB64));
  }

  // ─── Update check ────────────────────────────────────────────────────────────
  // Logic (runs every popup open):
  //
  //   1. Read 'updateCachedVersion' from chrome.storage.local.
  //   2. If cached version == installed version → user just updated → clear & done.
  //   3. If cached version > installed version → update still pending → show buttons,
  //      skip fetch (no network spam).
  //   4. No cache → fetch updates.json → if a newer version is found, store it
  //      permanently and show buttons.  If not, store nothing.
  //
  // The cached value is ONLY the version string (e.g. "0.5.2"), stored permanently.
  // It is cleared only when installed version catches up to it (step 2).

  const UPDATES_URL       = 'https://raw.githubusercontent.com/SenseiDeElite/discord-age-encryption/refs/heads/main/updates.json';
  const RELEASE_URL       = 'https://github.com/SenseiDeElite/discord-age-encryption/releases/latest';
  const UPDATE_CACHE_KEY  = 'updateCachedVersion';
  const UPDATE_CHECK_KEY  = 'updateCheckLog'; // { date: "YYYY-MM-DD", count: number }
  const UPDATE_MAX_CHECKS = 3; // max fetches per calendar day

  function parseSemver(v) {
    return (v ?? '').split('.').map(n => parseInt(n, 10) || 0);
  }

  function semverGt(a, b) {
    const pa = parseSemver(a), pb = parseSemver(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pa[i] || 0) - (pb[i] || 0);
      if (diff > 0) return true;
      if (diff < 0) return false;
    }
    return false;
  }

  function showUpdateButtons() {
    const openRelease = () => chrome.tabs.create({ url: RELEASE_URL });
    const el = document.getElementById('btn-update');
    if (!el) return;
    const fresh = el.cloneNode(true);
    fresh.hidden = false;
    fresh.title  = 'Update available';
    fresh.setAttribute('aria-label', 'Update available');
    fresh.addEventListener('click', openRelease);
    el.replaceWith(fresh);
  }

  async function canFetchUpdate() {
    const today = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
    const stored = await store.get([UPDATE_CHECK_KEY]);
    const log    = stored[UPDATE_CHECK_KEY] ?? { date: '', count: 0 };
    const count  = log.date === today ? log.count : 0;
    if (count >= UPDATE_MAX_CHECKS) return false;
    await store.set({ [UPDATE_CHECK_KEY]: { date: today, count: count + 1 } });
    return true;
  }

  // Firefox extensions published on AMO must declare browser_specific_settings.gecko
  // (AMO requirement for extension ID assignment).  Chrome never has this field in
  // the manifest, making it a reliable, zero-cost browser discriminator.
  function isFirefox() {
    return !!chrome.runtime.getManifest().browser_specific_settings?.gecko;
  }

  async function checkForUpdate() {
    if (isFirefox()) return; // Firefox manages its own updates via manifest update_url
    try {
      const current = chrome.runtime.getManifest().version;
      const stored  = await store.get([UPDATE_CACHE_KEY]);
      const cached  = stored[UPDATE_CACHE_KEY] ?? null;

      if (cached && !semverGt(cached, current)) {
        await store.remove([UPDATE_CACHE_KEY]);
        return;
      }

      if (cached && semverGt(cached, current)) {
        showUpdateButtons();
        return;
      }

      if (!(await canFetchUpdate())) return;

      let latest = '0.0.0';
      try {
        // AbortController enforces a hard timeout so a stalled CDN connection
        // does not leave this fire-and-forget promise open indefinitely.
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), 6000);
        try {
          const resp = await fetch(UPDATES_URL, { cache: 'no-store', signal: controller.signal });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          const data = await resp.json();
          for (const addon of Object.values(data.addons ?? {})) {
            for (const entry of addon.updates ?? []) {
              if (semverGt(entry.version, latest)) latest = entry.version;
            }
          }
        } finally {
          clearTimeout(timeoutId);
        }
      } catch {
        return; // network/parse/abort failure — silently skip, don't cache anything
      }

      if (semverGt(latest, current)) {
        await store.set({ [UPDATE_CACHE_KEY]: latest });
        showUpdateButtons();
      }

    } catch {
      // Unexpected error (e.g. storage unavailable) — never break the popup
    }
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
        const s = await chrome.storage.session.get('age_contacts');
        if (s.age_contacts && typeof s.age_contacts === 'object')
          _contacts = s.age_contacts;
      } catch {}

      // showMain() shows the screen immediately but its contact-load/broadcast
      // tail is async; stash the promise so checkPendingImport() can wait 
      // for it to fully settle before mutating _contacts — otherwise 
      // an import could race loadContacts()'s reassignment of _contacts and 
      // silently get reverted in memory.
      _mainReadyPromise = showMain();

      // Re-sync with the background in parallel; showMain's own loadContacts()
      // call will refresh the list once the key is available.
      bgUnlockResume(identity).catch(e =>
        console.warn('[age] bgUnlockResume failed:', e?.message));
    } else {
      // If the popup was dismissed mid-unlock, a stale doUnlock() may still be
      // racing in the background. Clear any partial session data it may have
      // written before we booted, then show a clean lock screen.
      // The user just needs to enter their passphrase once more (~1.6 s with Argon2id).
      try {
        const s = await chrome.storage.session.get('pending_unlock');
        if (s.pending_unlock) await clearSession();
      } catch {}
      document.getElementById('btn-goto-setup').hidden = false;
      await showLockScreen();
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
  // resetToSetupScreen: shared teardown for reset-keypair and clear-all-data.
  // clearSetupFields: true when arriving from the lock screen (setup fields visible).
  async function resetToSetupScreen(clearSetupFields = false) {
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
    document.getElementById('unlock-error').hidden     = true;
    if (clearSetupFields) {
      document.getElementById('setup-passphrase').value  = '';
      document.getElementById('setup-passphrase2').value = '';
      document.getElementById('setup-error').hidden      = true;
    }
    show('setup');
  }

  document.getElementById('btn-reset-confirm').addEventListener('click', async () => {
    document.getElementById('modal-reset-keypair').hidden = true;
    await resetToSetupScreen(true);
  });

  // ─── Passphrase lockdown ──────────────────────────────────────────────────────
  // Exactly 3 consecutive wrong attempts → 10-minute lockdown, then counter resets.
  // No exponential escalation — every lockout is a flat 10 minutes.
  // State is persisted in chrome.storage.local so closing/reopening the popup
  // cannot bypass the lockout.
  // Storage keys: unlockAttempts (int 0–2), unlockLockedUntil (ms timestamp or 0).

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
    const btn   = document.getElementById('btn-unlock');
    const errEl = document.getElementById('unlock-error');
    const inp   = document.getElementById('passphrase-input');

    if (_lockCountdownInterval) { clearInterval(_lockCountdownInterval); _lockCountdownInterval = null; }

    if (!lockedUntilMs || Date.now() >= lockedUntilMs) {
      _isLockedOut = false;
      btn.disabled = false;
      inp.disabled = false;
      errEl.hidden = true;
      return;
    }

    _isLockedOut = true;
    btn.disabled    = true;
    btn.textContent = 'Unlock'; // reset from any in-progress label (e.g. 'Unlocking…')
    inp.disabled    = true;

    function tick() {
      const remaining = lockedUntilMs - Date.now();
      if (remaining <= 0) {
        clearInterval(_lockCountdownInterval);
        _lockCountdownInterval = null;
        _isLockedOut = false;
        btn.disabled = false;
        inp.disabled = false;
        errEl.hidden = true;
        // Clear the lockout record so the next 3 failures start a fresh lockout.
        store.set({ unlockAttempts: 0, unlockLockedUntil: 0 });
        return;
      }
      showErr(errEl, `Too many failed attempts. Try again in ${fmtCountdown(remaining)}.`);
    }
    tick();
    _lockCountdownInterval = setInterval(tick, 1000);
  }

  async function checkLockdown() {
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
    if (unlockAttempts > 0) {
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
    document.getElementById('unlock-error').hidden    = true;
    // Reset button state in case we're transitioning from an in-progress unlock.
    const btn = document.getElementById('btn-unlock');
    if (!_isLockedOut) {
      btn.disabled    = false;
      btn.textContent = 'Unlock';
    }
    document.getElementById('passphrase-input').disabled = _isLockedOut;
    show('lock');
    await checkLockdown();
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
      showErr(
        document.getElementById('unlock-error'),
        `Wrong passphrase. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`
      );
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
    errEl.hidden = true;

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

      // Detect old age-scrypt format (not our 0x01 envelope).
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
      const mldsaPubB64 = toB64(mldsaPub);

      // Rebuild the full recipient string if it was stored without the suffix
      // (migration: old entries may not have the ;mldsa87: component yet).
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
      await bgUnlock(identity, passphrase);
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
        // Wrong passphrase — record against lockdown counter.
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

  // Rejects non-ASCII and control chars that could break JSON serialisation or protocol fields.
  function isPrintableAscii(s) {
    return /^[\x20-\x7E]+$/.test(s);
  }

  function validatePassphrase(p) {
    const errs = [];
    if (p.length < 20)           errs.push('at least 20 characters');
    if (!/[A-Z]/.test(p))        errs.push('an uppercase letter (A–Z)');
    if (!/[a-z]/.test(p))        errs.push('a lowercase letter (a–z)');
    if (!/[0-9]/.test(p))        errs.push('a number (0–9)');
    if (!/[^A-Za-z0-9]/.test(p)) errs.push('a special character (e.g. !&*)');
    return errs.length ? 'Passphrase must include: ' + errs.join(', ') + '.' : null;
  }

  document.getElementById('btn-generate').addEventListener('click', async () => {
    await cryptoReady;
    const pass  = setupPassEl.value;
    const pass2 = document.getElementById('setup-passphrase2').value;
    const errEl = document.getElementById('setup-error');
    errEl.hidden = true;

    const passErr = validatePassphrase(pass);
    if (passErr)        { showErr(errEl, passErr); return; }
    if (pass !== pass2) { showErr(errEl, 'Passphrases do not match.'); return; }

    document.getElementById('btn-generate').hidden  = true;
    document.getElementById('btn-show-import').hidden = true;
    document.getElementById('setup-spinner').hidden = false;

    try {
      const identity  = await generateHybridIdentity();
      const recipient = await identityToRecipient(identity);

      // Generate ML-DSA-87 keypair for message authentication.
      // ml_dsa87_keygen() returns seed(32)||verifyingKey(2592) = 2624 bytes total.
      // We store only the seed — the verifying key is re-derived at unlock time
      // via ml_dsa87_verifying_key_from_seed(seed).  This keeps the identity
      // blob compact and makes the mldsa87pub: line unnecessary.
      const mldsaRaw     = ml_dsa87_keygen();              // 2624 bytes: seed(32)||vk(2592)
      const mldsaSeed    = mldsaRaw.slice(0, 32);          // 32-byte seed — the private key
      const mldsaPub     = mldsaRaw.slice(32);             // 2592-byte verifying key
      const mldsaSeedB64 = toB64(mldsaSeed);
      const mldsaPubB64  = toB64(mldsaPub);

      // Identity blob (2 lines):
      //   AGE-SECRET-KEY-PQ-1… — age ML-KEM-768×X25519 hybrid private key
      //   mldsa87seed:<b64>     — 32-byte ML-DSA-87 seed (standard base64, 44 chars)
      //
      // The seed is all that is stored.  At unlock the verifying key is re-derived
      // via ml_dsa87_verifying_key_from_seed(seed), so both signing and recipient
      // strings can always be reconstructed without storing the large keys.
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
      await showMain();

    } catch (e) {
      showErr(document.getElementById('setup-error'), 'Key generation failed: ' + e.message);
    } finally {
      document.getElementById('btn-generate').hidden  = false;
      document.getElementById('btn-show-import').hidden = false;
      document.getElementById('setup-spinner').hidden = true;
    }
  });

  // ─── Import existing keypair ─────────────────────────────────────────────────

  const DRAFT_TTL = 10 * 60 * 1000;

  function makeDraftManager(sessionKey, fieldIds) {
    async function save() {
      const draft = { ts: Date.now() };
      fieldIds.forEach(id => { draft[id] = document.getElementById(id).value; });
      try { await chrome.storage.session.set({ [sessionKey]: draft }); } catch {}
    }
    async function restore() {
      try {
        const result = await chrome.storage.session.get(sessionKey);
        const draft = result[sessionKey];
        if (!draft || Date.now() - draft.ts > DRAFT_TTL) return false;
        fieldIds.forEach(id => { if (draft[id]) document.getElementById(id).value = draft[id]; });
        return fieldIds.some(id => document.getElementById(id).value.trim());
      } catch { return false; }
    }
    async function clear() {
      try { await chrome.storage.session.remove(sessionKey); } catch {}
    }
    return { save, restore, clear };
  }

  const IMPORT_DRAFT_FIELDS = ['import-blob', 'import-export-passphrase', 'import-passphrase', 'import-passphrase2'];
  const { save: saveImportDraft, restore: restoreImportDraft, clear: clearImportDraft } =
    makeDraftManager('import_draft', IMPORT_DRAFT_FIELDS);

  IMPORT_DRAFT_FIELDS.forEach(id => document.getElementById(id).addEventListener('input', saveImportDraft));
  document.getElementById('btn-show-import').addEventListener('click', () => show('import'));
  document.getElementById('btn-back-import').addEventListener('click', () => show('setup'));

  document.getElementById('btn-import').addEventListener('click', async () => {
    await cryptoReady;
    const encryptedBlob  = document.getElementById('import-blob').value.trim();
    const exportPass     = document.getElementById('import-export-passphrase').value;
    const newPass        = document.getElementById('import-passphrase').value;
    const newPass2       = document.getElementById('import-passphrase2').value;
    const errEl          = document.getElementById('import-error');
    errEl.hidden = true;

    if (!encryptedBlob)    { showErr(errEl, 'Paste your encrypted private key blob first.'); return; }
    if (!exportPass)       { showErr(errEl, 'Enter the export passphrase used when the blob was created.'); return; }

    const passErr = validatePassphrase(newPass);
    if (passErr)           { showErr(errEl, passErr); return; }
    if (newPass !== newPass2) { showErr(errEl, 'Passphrases do not match.'); return; }

    const btn = document.getElementById('btn-import');
    btn.hidden = true;
    document.getElementById('import-spinner').hidden = false;

    try {
      // The export blob from "My Key → Export" is always encrypted with the
      // new XChaCha20 envelope format (version 0x01).  Old age-scrypt exports
      // will produce an OUTDATED_FORMAT error with a clear message.
      let identityBlob;
      try {
        identityBlob = await decryptIdentityBlob(encryptedBlob, exportPass);
      } catch (e) {
        if (e.message === 'CORRUPT_BLOB') {
          throw new Error('The pasted blob appears truncated or corrupt. Please copy it again in full.');
        }
        if (e.message === 'OUTDATED_FORMAT') {
          throw new Error('This export was created with an older version of the extension. ' +
            'Please regenerate your keypair on the original device and export again.');
        }
        throw new Error('Wrong export passphrase, or the blob is not a valid encrypted key export.');
      }

      const lines = identityBlob.split('\n');
      if (!lines[0].startsWith('AGE-SECRET-KEY-1') && !lines[0].startsWith('AGE-SECRET-KEY-PQ-1'))
        throw new Error('Decrypted content is not a valid age identity (expected AGE-SECRET-KEY-1… or AGE-SECRET-KEY-PQ-1…).');
      if (!lines[1]?.startsWith('mldsa87seed:'))
        throw new Error('Decrypted identity is missing an ML-DSA-87 seed (expected mldsa87seed:…).');

      const identity  = lines[0];
      const recipient = await identityToRecipient(identity);

      // Re-derive the ML-DSA-87 verifying key from the stored seed.
      const mldsaSeed    = fromB64(lines[1].slice('mldsa87seed:'.length));
      const mldsaPub     = ml_dsa87_verifying_key_from_seed(mldsaSeed);
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
      showErr(errEl, 'Import failed: ' + e.message);
    } finally {
      btn.hidden = false;
      document.getElementById('import-spinner').hidden = true;
    }
  });

  // ─── Main screen ─────────────────────────────────────────────────────────────

  async function showMain() {
    const data = await store.get(['globalOn']);
    _globalOn = data.globalOn !== false;

    // Show the screen immediately — never let an async failure below block the
    // transition.  The passphrase field was already cleared by doUnlock; leaving
    // the lock screen visible after a successful crypto operation is the bug.
    document.getElementById('global-toggle').checked = _globalOn;
    document.getElementById('contacts-search').value = '';
    renderContacts();
    show('main');

    checkForUpdate(); // fire-and-forget; only fetches if no cache exists

    // Load and broadcast contacts after the screen is already visible.
    // loadContacts() can fail silently (e.g. contacts key momentarily unavailable)
    // and that must not roll back the screen state.
    try {
      _contacts = await loadContacts();
    } catch (e) {
      console.warn('[age] showMain: loadContacts failed:', e?.message);
    }
    renderContacts(); // re-render with the now-populated contacts list
    // Broadcast the freshly-loaded contacts to all Discord tabs.  This must
    // happen after _contacts is populated — the UNLOCK broadcast in bgUnlock()
    // fires before loadContacts() completes and carries a stale empty object.
    await bgContactsUpdated();
  }

  document.getElementById('global-toggle').addEventListener('change', async (e) => {
    _globalOn = e.target.checked;
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

  // Validate a full age recipient string (age1pq1… + ;mldsa87:… suffix).
  // Returns null on success, error string on failure.
  // Only X25519+MLKEM768 hybrid keys (age1pq1…) are accepted.
  // Validates structurally — bech32 charset + length bounds for the age1pq1 portion,
  // and the existing regex for the ML-DSA-87 suffix — without performing live
  // key agreement.  Hybrid keys are ~1958 chars; the body allows '1' since the
  // bech32 format uses it as an internal separator in the data payload.
  function validateRecipient(recipient) {
    if (!recipient.startsWith('age1pq1'))
      return 'Public key must start with "age1pq1…" (X25519+MLKEM768 hybrid key).';
    if (recipient.startsWith('AGE-SECRET-KEY-'))
      return 'That is a private key — paste their public key (age1pq1…) instead.';
    if (!/;mldsa87:[A-Za-z0-9+/]+=*$/.test(recipient))
      return 'Public key must be the full key including the ML-DSA-87 component (age1pq1…;mldsa87:…).';
    // Validate the age1pq1 portion: bech32 charset including '1' (used as an
    // internal separator in the hybrid format), length ~1958 chars total.
    const agePart = recipient.split(';')[0];
    if (!/^age1pq1[ac-hj-np-z02-91]{50,1960}$/.test(agePart))
      return 'age1pq1... key appears malformed — check that it was copied correctly.';
    return null;
  }

  // Validate a contact's fields for add/edit.
  // editingUUID: the UUID being edited (null for new contacts) — excluded from
  // duplicate checks so editing without changes doesn't falsely report a conflict.
  function validateContactFields(channelId, username, recipient, editingUUID = null) {
    if (!channelId || !username || !recipient)
      return 'All fields are required.';
    if (!/^\d+$/.test(channelId))
      return 'Channel ID must contain digits only.';
    if (channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID)
      return `Channel ID must be ${MIN_CHANNEL_ID}–${MAX_CHANNEL_ID} digits.`;
    if (username.length < MIN_USERNAME || username.length > MAX_USERNAME)
      return `Contact name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`;
    if (!isPrintableAscii(username))
      return 'Contact name must contain printable ASCII characters only.';

    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue; // skip the contact being edited
      if (c.channelId === channelId)
        return 'A contact with this Channel ID already exists.';
      if (c.username === username)
        return `The name "${username}" is already used by another contact.`;
      if (c.ageRecipient === recipient)
        return 'This public key is already assigned to another contact.';
    }
    return null;
  }

  // validateGroupFields: mirrors validateContactFields for group add/edit.
  // editingUUID: UUID being edited (null for new groups) — excluded from duplicate check.
  function validateGroupFields(channelId, name, editingUUID = null) {
    if (!channelId) return 'Channel ID is required.';
    if (!/^\d+$/.test(channelId) || channelId.length < MIN_CHANNEL_ID || channelId.length > MAX_CHANNEL_ID)
      return `Channel ID must be ${MIN_CHANNEL_ID}–${MAX_CHANNEL_ID} digits.`;
    if (!name || name.length < MIN_USERNAME || name.length > MAX_USERNAME)
      return `Name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`;
    if (!isPrintableAscii(name)) return 'Name must contain printable ASCII characters only.';
    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue;
      if (c.channelId === channelId) return 'A contact or group with this Channel ID already exists.';
    }
    return null;
  }

  // validateServerFields: mirrors validateContactFields for server add/edit.
  // editingUUID: UUID being edited (null for new servers) — excluded from duplicate check.
  function validateServerFields(serverId, name, editingUUID = null) {
    if (!serverId || !/^\d{1,20}$/.test(serverId)) return 'Server ID must be 1–20 digits.';
    if (!name || name.length < MIN_USERNAME || name.length > MAX_USERNAME)
      return `Name must be ${MIN_USERNAME}–${MAX_USERNAME} characters.`;
    if (!isPrintableAscii(name)) return 'Name must contain printable ASCII characters only.';
    for (const [uuid, c] of Object.entries(_contacts)) {
      if (uuid === editingUUID) continue;
      if (c.type === 'server' && c.serverId === serverId) return 'A server with this Server ID already exists.';
    }
    return null;
  }

  // ─── Contacts list ────────────────────────────────────────────────────────────

  function renderContacts(query = '') {
    const list  = document.getElementById('contacts-list');
    const empty = document.getElementById('no-contacts');
    list.querySelectorAll('.contact-card').forEach(el => el.remove());

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

    empty.hidden = entries.length > 0;

    entries.forEach(c => {
      const uuid = c.id;
      const card = document.createElement('div');
      card.className = 'contact-card';

      const type   = c.type ?? 'contact';
      const icon   = type === 'group' ? '👥' : type === 'server' ? '🌐' : '👤';
      const label  = type === 'contact' ? c.username : c.name;

      const avatar = Object.assign(document.createElement('div'), {
        className:   'contact-avatar',
        textContent: icon,
      });
      const name = Object.assign(document.createElement('div'), {
        className:   'contact-name',
        textContent: label,
      });
      const chipLabel = c.enabled ? '🔒 Encrypted' : '🔓 Disabled';
      const chip = Object.assign(document.createElement('span'), {
        className:   `contact-chip ${c.enabled ? 'chip-on' : 'chip-off'}`,
        textContent: chipLabel,
      });
      const info = document.createElement('div');
      info.className = 'contact-info';
      info.append(name, chip);
      card.append(avatar, info);

      card.addEventListener('click', () => {
        if (type === 'group')  openGroupSheet(uuid);
        else if (type === 'server') openServerSheet(uuid);
        else openContactSheet(uuid);
      });
      list.appendChild(card);
    });
  }

  document.getElementById('contacts-search').addEventListener('input', e => {
    renderContacts(e.target.value);
  });

  // ─── FAB / unified add screen ─────────────────────────────────────────────────

  function resetAddScreen() {
    document.getElementById('add-type-select').value = 'contact';
    document.getElementById('add-fields-contact').hidden = false;
    document.getElementById('add-fields-group').hidden   = true;
    document.getElementById('add-fields-server').hidden  = true;
    document.getElementById('add-contact-error').hidden  = true;
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

  document.getElementById('add-type-select').addEventListener('change', async (e) => {
    const type = e.target.value;
    document.getElementById('add-fields-contact').hidden = type !== 'contact';
    document.getElementById('add-fields-group').hidden   = type !== 'group';
    document.getElementById('add-fields-server').hidden  = type !== 'server';
    document.getElementById('add-contact-error').hidden  = true;
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

  async function inferFromTab(pattern) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const m = (tabs[0]?.url ?? '').match(pattern);
    return m ? m[1] : null;
  }

  // inferDmChannelId: extracts the channel ID from DM URLs only
  //   (/channels/@me/<id>).  Returns null for server channel URLs
  //   (/channels/<serverId>/<channelId>) — use inferServerId for those.
  const inferDmChannelId = () => inferFromTab(/discord\.com\/channels\/@me\/(\d+)/);
  const inferServerId    = () => inferFromTab(/discord\.com\/channels\/(\d+)\/\d+/);

  document.getElementById('btn-back-add').addEventListener('click', async () => {
    await clearDraft();
    resetAddScreen();
    showMain();
  });

  document.getElementById('btn-save-contact').addEventListener('click', async () => {
    const type  = document.getElementById('add-type-select').value;
    const errEl = document.getElementById('add-contact-error');
    errEl.hidden = true;

    if (type === 'contact') {
      const channelId = document.getElementById('contact-channel-id').value.trim();
      const username  = document.getElementById('contact-username').value.trim();
      const recipient = document.getElementById('contact-key').value.trim();

      const fieldErr = validateContactFields(channelId, username, recipient, null);
      if (fieldErr) { showErr(errEl, fieldErr); return; }
      const recipErr = validateRecipient(recipient);
      if (recipErr)  { showErr(errEl, recipErr); return; }

      const contactCount = Object.values(_contacts).filter(c => c.type === 'contact' || !c.type).length;
      if (contactCount >= MAX_CONTACTS) { showErr(errEl, `Contact limit reached (${MAX_CONTACTS} max).`); return; }

      const uuid = crypto.randomUUID();
      _contacts[uuid] = { id: uuid, type: 'contact', channelId, username, ageRecipient: recipient, enabled: true };

    } else if (type === 'group') {
      const channelId = document.getElementById('group-channel-id').value.trim();
      const name      = document.getElementById('group-name').value.trim();

      const groupErr = validateGroupFields(channelId, name, null);
      if (groupErr) { showErr(errEl, groupErr); return; }
      if (_groupAddMembers.length < 1) { showErr(errEl, 'Select at least 1 member.'); return; }

      const uuid = crypto.randomUUID();
      _contacts[uuid] = { id: uuid, type: 'group', channelId, name, memberIds: _groupAddMembers, enabled: true };

    } else if (type === 'server') {
      const serverId = document.getElementById('server-id-input').value.trim();
      const name     = document.getElementById('server-name').value.trim();

      const serverErr = validateServerFields(serverId, name, null);
      if (serverErr) { showErr(errEl, serverErr); return; }
      const serverCount = Object.values(_contacts).filter(c => c.type === 'server').length;
      if (serverCount >= MAX_SERVERS) { showErr(errEl, `Server limit reached (${MAX_SERVERS} max).`); return; }
      if (_serverAddMembers.length < 1) { showErr(errEl, 'Select at least 1 member.'); return; }

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
    });
  });

  // ─── Contact sheet ───────────────────────────────────────────────────────────

  async function openContactSheet(uuid) {
    _selectedId = uuid;
    const c    = _contacts[uuid];
    const fpEl = document.getElementById('sheet-contact-fp');
    document.getElementById('sheet-contact-name').textContent = c.username;
    document.getElementById('sheet-contact-toggle').checked   = c.enabled;
    fpEl.textContent = 'Computing…';
    document.getElementById('sheet-contact').hidden  = false;
    document.getElementById('sheet-backdrop').hidden = false;
    fpEl.textContent = await keyFingerprint(c.ageRecipient);
  }

  function closeSheet() {
    document.getElementById('sheet-contact').hidden = true;
    document.getElementById('sheet-group').hidden   = true;
    document.getElementById('sheet-server').hidden  = true;
    document.getElementById('sheet-backdrop').hidden = true;
    _selectedId       = null;
    _selectedGroupId  = null;
    _selectedServerId = null;
  }

  document.getElementById('btn-close-sheet').addEventListener('click', closeSheet);
  document.getElementById('sheet-backdrop').addEventListener('click', closeSheet);

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
    document.getElementById('modal-delete-contact').hidden = false;
  });

  document.getElementById('btn-delete-cancel').addEventListener('click', () => {
    document.getElementById('modal-delete-contact').hidden = true;
  });

  document.getElementById('btn-delete-confirm').addEventListener('click', async () => {
    document.getElementById('modal-delete-contact').hidden = true;
    if (_selectedId) {
      const deletedId = _selectedId;
      delete _contacts[deletedId];
      // Remove the deleted contact from any group/server member lists.
      for (const entry of Object.values(_contacts)) {
        if (Array.isArray(entry.memberIds)) {
          entry.memberIds = entry.memberIds.filter(id => id !== deletedId);
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
    closeSheet();
    renderContacts();
  });

  document.getElementById('btn-edit-contact').addEventListener('click', () => {
    if (!_selectedId) return;
    const c = _contacts[_selectedId];
    document.getElementById('edit-channel-id').value = c.channelId;
    document.getElementById('edit-username').value   = c.username;
    document.getElementById('edit-key').value        = c.ageRecipient;
    document.getElementById('edit-contact-error').hidden = true;
    _editingId = _selectedId;
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

    const fieldErr = validateContactFields(channelId, username, recipient, _editingId);
    if (fieldErr) { showErr(errEl, fieldErr); return; }

    const recipErr = validateRecipient(recipient);
    if (recipErr)  { showErr(errEl, recipErr); return; }

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
    });
  });

  // ─── Member picker ────────────────────────────────────────────────────────────
  // Shared bottom-sheet used by both group and server creation/edit screens.
  // _pickerContext: { mode: 'add-group'|'edit-group'|'add-server'|'edit-server',
  //                   maxMembers: number, selectedUUIDs: Set<string> }

  let _pickerContext = null;

  function contactsForPicker() {
    return Object.values(_contacts).filter(c => c.type === 'contact' || !c.type);
  }

  function renderMemberPicker(query = '') {
    const list = document.getElementById('member-picker-list');
    list.innerHTML = '';
    const q = query.trim().toLowerCase();
    const contacts = contactsForPicker().filter(c =>
      !q || c.username.toLowerCase().includes(q)
    );
    const maxMembers = _pickerContext?.maxMembers ?? Infinity;
    contacts.forEach(c => {
      const checked = _pickerContext?.selectedUUIDs.has(c.id) ?? false;
      const row = document.createElement('label');
      row.className = 'member-picker-row';
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
      });
      const lbl = document.createElement('span');
      lbl.textContent = c.username;
      row.append(cb, lbl);
      list.appendChild(row);
    });
    if (!contacts.length) {
      const msg = document.createElement('p');
      msg.style.cssText = 'color:var(--md-on-surface-variant);font-size:13px;padding:16px;text-align:center;';
      msg.textContent = q ? 'No contacts match.' : 'No contacts yet — add contacts first.';
      list.appendChild(msg);
    }
  }

  function openMemberPicker(context) {
    _pickerContext = context;
    document.getElementById('member-picker-search').value = '';
    renderMemberPicker('');
    document.getElementById('sheet-member-picker').hidden          = false;
    document.getElementById('sheet-member-picker-backdrop').hidden = false;
  }

  function closeMemberPicker() {
    document.getElementById('sheet-member-picker').hidden          = true;
    document.getElementById('sheet-member-picker-backdrop').hidden = true;
  }

  document.getElementById('member-picker-search').addEventListener('input', e => {
    renderMemberPicker(e.target.value);
  });
  document.getElementById('btn-member-picker-done').addEventListener('click', () => {
    closeMemberPicker();
    if (!_pickerContext) return;
    const uuids = [..._pickerContext.selectedUUIDs];
    applyMemberSelection(_pickerContext.mode, uuids);
  });
  document.getElementById('sheet-member-picker-backdrop').addEventListener('click', closeMemberPicker);

  // ─── Member chip rendering (used by group/server forms) ───────────────────────

  function renderMemberChips(containerEl, countEl, uuids, maxMembers) {
    containerEl.innerHTML = '';
    const displayMax = maxMembers === Infinity ? '' : ` / ${maxMembers}`;
    if (countEl) countEl.textContent = `(${uuids.length}${displayMax})`;
    uuids.forEach(uuid => {
      const c = _contacts[uuid];
      if (!c) return;
      const chip = document.createElement('span');
      chip.className   = 'member-chip';
      chip.textContent = c.username;
      containerEl.appendChild(chip);
    });
  }

  function applyMemberSelection(mode, uuids) {
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
      document.getElementById('group-member-list').innerHTML = '';
      document.getElementById('group-member-count').textContent = `(0 / ${MAX_GROUP_MEMBERS})`;
    } else {
      _groupEditMembers = [];
      document.getElementById('edit-group-channel-id').value = '';
      document.getElementById('edit-group-name').value       = '';
      document.getElementById('edit-group-member-list').innerHTML = '';
      document.getElementById('edit-group-member-count').textContent = `(0 / ${MAX_GROUP_MEMBERS})`;
      document.getElementById('edit-group-error').hidden = true;
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
    errEl.hidden    = true;

    const groupErr = validateGroupFields(channelId, name, _editingGroupId);
    if (groupErr) { showErr(errEl, groupErr); return; }
    if (_groupEditMembers.length < 1) { showErr(errEl, 'Select at least 1 member.'); return; }

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
    });
  });

  // ─── Group sheet ──────────────────────────────────────────────────────────────

  async function openGroupSheet(uuid) {
    _selectedGroupId = uuid;
    const g = _contacts[uuid];
    document.getElementById('sheet-group-name').textContent    = g.name;
    document.getElementById('sheet-group-channel').textContent = g.channelId;
    document.getElementById('sheet-group-toggle').checked      = g.enabled;
    document.getElementById('sheet-group').hidden              = false;
    document.getElementById('sheet-backdrop').hidden           = false;
  }

  document.getElementById('sheet-group-toggle').addEventListener('change', async e => {
    if (!_selectedGroupId) return;
    _contacts[_selectedGroupId].enabled = e.target.checked;
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();
  });

  document.getElementById('btn-edit-group').addEventListener('click', () => {
    if (!_selectedGroupId) return;
    const g = _contacts[_selectedGroupId];
    _editingGroupId   = _selectedGroupId;
    _groupEditMembers = [...(g.memberIds ?? [])];
    document.getElementById('edit-group-channel-id').value = g.channelId;
    document.getElementById('edit-group-name').value       = g.name;
    document.getElementById('edit-group-error').hidden     = true;
    renderMemberChips(
      document.getElementById('edit-group-member-list'),
      document.getElementById('edit-group-member-count'),
      _groupEditMembers, MAX_GROUP_MEMBERS
    );
    closeSheet();
    show('edit-group');
  });

  document.getElementById('btn-delete-group').addEventListener('click', () => {
    if (!_selectedGroupId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedGroupId].name}" group will be permanently removed.`;
    document.getElementById('modal-delete-contact').hidden = false;
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
      document.getElementById('server-member-list').innerHTML = '';
      document.getElementById('server-member-count').textContent = '(0)';
    } else {
      _serverEditMembers = [];
      document.getElementById('edit-server-id-input').value = '';
      document.getElementById('edit-server-name').value     = '';
      document.getElementById('edit-server-member-list').innerHTML = '';
      document.getElementById('edit-server-member-count').textContent = '(0)';
      document.getElementById('edit-server-error').hidden = true;
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
    errEl.hidden   = true;

    const serverErr = validateServerFields(serverId, name, _editingServerId);
    if (serverErr) { showErr(errEl, serverErr); return; }
    if (_serverEditMembers.length < 1) { showErr(errEl, 'Select at least 1 member.'); return; }

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
    });
  });

  // ─── Server sheet ─────────────────────────────────────────────────────────────

  async function openServerSheet(uuid) {
    _selectedServerId = uuid;
    const s = _contacts[uuid];
    document.getElementById('sheet-server-name').textContent       = s.name;
    document.getElementById('sheet-server-id-display').textContent = s.serverId;
    document.getElementById('sheet-server-toggle').checked         = s.enabled;
    document.getElementById('sheet-server').hidden                 = false;
    document.getElementById('sheet-backdrop').hidden               = false;
  }

  document.getElementById('sheet-server-toggle').addEventListener('change', async e => {
    if (!_selectedServerId) return;
    _contacts[_selectedServerId].enabled = e.target.checked;
    await saveContacts(_contacts);
    await bgContactsUpdated();
    renderContacts();
  });

  document.getElementById('btn-edit-server').addEventListener('click', () => {
    if (!_selectedServerId) return;
    const s = _contacts[_selectedServerId];
    _editingServerId   = _selectedServerId;
    _serverEditMembers = [...(s.memberIds ?? [])];
    document.getElementById('edit-server-id-input').value = s.serverId;
    document.getElementById('edit-server-name').value     = s.name;
    document.getElementById('edit-server-error').hidden   = true;
    renderMemberChips(
      document.getElementById('edit-server-member-list'),
      document.getElementById('edit-server-member-count'),
      _serverEditMembers, Infinity
    );
    closeSheet();
    show('edit-server');
  });

  document.getElementById('btn-delete-server').addEventListener('click', () => {
    if (!_selectedServerId) return;
    document.getElementById('modal-delete-msg').textContent =
      `"${_contacts[_selectedServerId].name}" server will be permanently removed.`;
    document.getElementById('modal-delete-contact').hidden = false;
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
      download: `discord_age_contacts_${datePart}.json`,
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

    // Reject oversized files before JSON.parse to prevent freezing the UI thread.
    if (json.length > IMPORT_SIZE_LIMIT) {
      msgEl.textContent = 'File too large — contacts exports must be under 1 MB.';
      modal.hidden = false;
      return;
    }

    let parsed;
    try { parsed = JSON.parse(json); }
    catch {
      msgEl.textContent = 'Could not parse file — make sure it is a valid contacts export.';
      modal.hidden = false;
      return;
    }

    // Reject v1 outright (version !== 2, or bare array without version field).
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.version !== CONTACTS_VERSION) {
      msgEl.textContent = 'Unsupported format — only v2 exports (version: 2) are accepted. v1 imports are no longer supported.';
      modal.hidden = false;
      return;
    }

    const entries = parsed.entries;
    if (!Array.isArray(entries)) {
      msgEl.textContent = 'Unrecognised format — expected a v2 contacts export JSON with an "entries" array.';
      modal.hidden = false;
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
    chrome.tabs.remove(id).catch(() => {});
  }

  async function checkPendingImport() {
    try {
      const data = await chrome.storage.session.get(['pending_import', 'pending_import_tab']);
      if (!data.pending_import) return;
      // If the vault is locked at this point, the user must have manually locked it
      if (document.getElementById('screen-lock').hidden === false) {
        await chrome.storage.session.remove(['pending_import', 'pending_import_tab']);
        if (data.pending_import_tab != null)
          chrome.tabs.remove(data.pending_import_tab).catch(() => {});
        return;
      }
      // showMain()'s tail reassigns _contacts from loadContacts() and
      // broadcasts it. If we ran the import concurrently with that, 
      // the import's mutation of _contacts could be silently clobbered by 
      // the later reassignment. Wait for it to fully settle first so 
      // we mutate the final, authoritative _contacts.
      if (_mainReadyPromise) {
        await _mainReadyPromise.catch(() => {});
        _mainReadyPromise = null;
      }
      _importHelperTabId = data.pending_import_tab ?? null;
      await chrome.storage.session.remove(['pending_import', 'pending_import_tab']);
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
    const ageRecipient = await getAgeRecipient();
    if (!ageRecipient) return;
    document.getElementById('my-key-box').textContent = ageRecipient;
    document.getElementById('my-key-fp').textContent = 'Computing fingerprint…';
    show('my-key');
    document.getElementById('my-key-fp').textContent = await keyFingerprint(ageRecipient);
  }

  document.getElementById('btn-copy-key').addEventListener('click', async () => {
    const ageRecipient = await getAgeRecipient();
    if (!ageRecipient) return;
    await navigator.clipboard.writeText(ageRecipient);
    const btn   = document.getElementById('btn-copy-key');
    const label = document.getElementById('btn-copy-key-label');
    btn.classList.add('copied');
    label.textContent = 'Copied!';
    setTimeout(() => {
      btn.classList.remove('copied');
      label.textContent = 'Copy';
    }, 1800);
  });

  // ─── Export private key ───────────────────────────────────────────────────────

  function resetExportModal() {
    document.getElementById('export-passphrase-input').value  = '';
    document.getElementById('export-new-passphrase').value    = '';
    document.getElementById('export-new-passphrase2').value   = '';
    document.getElementById('export-passphrase-error').hidden = true;
    document.getElementById('export-spinner').hidden          = true;
    document.getElementById('btn-export-confirm').disabled    = false;
    document.getElementById('btn-export-confirm').textContent = 'Encrypt & show';
    document.getElementById('modal-export-key').hidden        = true;
  }

  document.getElementById('btn-export-key').addEventListener('click', () => {
    resetExportModal();
    document.getElementById('modal-export-key').hidden = false;
  });

  document.getElementById('btn-export-cancel').addEventListener('click', resetExportModal);

  ['export-passphrase-input', 'export-new-passphrase', 'export-new-passphrase2'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('btn-export-confirm').click();
    });
  });

  document.getElementById('btn-export-confirm').addEventListener('click', async () => {
    const unlockPass  = document.getElementById('export-passphrase-input').value;
    const exportPass  = document.getElementById('export-new-passphrase').value;
    const exportPass2 = document.getElementById('export-new-passphrase2').value;
    const errEl       = document.getElementById('export-passphrase-error');
    const btn         = document.getElementById('btn-export-confirm');
    const spinner     = document.getElementById('export-spinner');

    errEl.hidden = true;
    if (!unlockPass) { showErr(errEl, 'Enter your unlock passphrase.'); return; }

    const exportPassErr = validatePassphrase(exportPass);
    if (exportPassErr)              { showErr(errEl, 'Export passphrase: ' + exportPassErr); return; }
    if (exportPass !== exportPass2) { showErr(errEl, 'Export passphrases do not match.'); return; }

    btn.disabled    = true;
    btn.textContent = 'Verifying…';
    spinner.hidden  = false;

    try {
      const identity = await loadAndDecryptIdentity(unlockPass, 'Wrong unlock passphrase.');

      btn.textContent = 'Encrypting…';
      const envelopeB64 = await encryptIdentityBlob(identity, exportPass);

      resetExportModal();
      document.getElementById('export-key-blob').value = envelopeB64;
      document.getElementById('modal-export-display').hidden = false;

    } catch (e) {
      showErr(errEl, e.message === 'OUTDATED_FORMAT'
        ? 'Your identity format is outdated. Please regenerate your key.'
        : 'Export failed: ' + e.message
      );
      btn.disabled    = false;
      btn.textContent = 'Encrypt & show';
      spinner.hidden  = true;
    }
  });

  function closeExportDisplay() {
    document.getElementById('export-key-blob').value          = '';
    document.getElementById('modal-export-display').hidden     = true;
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
    document.getElementById('setup-error').hidden      = true;
    show('setup');
  });

  // ─── Clear all data (from My Key screen) ─────────────────────────────────────

  document.getElementById('btn-clear-data').addEventListener('click', () => {
    document.getElementById('clear-data-confirm-input').value  = '';
    document.getElementById('btn-clear-data-confirm').disabled = true;
    document.getElementById('modal-clear-data').hidden         = false;
  });
  document.getElementById('btn-clear-data-cancel').addEventListener('click', () => {
    document.getElementById('clear-data-confirm-input').value = '';
    document.getElementById('modal-clear-data').hidden        = true;
  });
  document.getElementById('clear-data-confirm-input').addEventListener('input', e => {
    document.getElementById('btn-clear-data-confirm').disabled = (e.target.value !== 'CONFIRM');
  });
  document.getElementById('btn-clear-data-confirm').addEventListener('click', async () => {
    document.getElementById('modal-clear-data').hidden = true;
    await resetToSetupScreen(false);
  });

  // ─── Change passphrase ────────────────────────────────────────────────────────

  function resetChangePassModal() {
    document.getElementById('change-pass-current').value  = '';
    document.getElementById('change-pass-new').value      = '';
    document.getElementById('change-pass-new2').value     = '';
    document.getElementById('change-pass-error').hidden   = true;
    document.getElementById('change-pass-spinner').hidden = true;
    const btn = document.getElementById('btn-change-pass-confirm');
    btn.disabled    = false;
    btn.textContent = 'Change passphrase';
    document.getElementById('modal-change-passphrase').hidden = true;
  }

  document.getElementById('btn-change-passphrase').addEventListener('click', () => {
    resetChangePassModal();
    document.getElementById('modal-change-passphrase').hidden = false;
  });

  document.getElementById('btn-change-pass-cancel').addEventListener('click', resetChangePassModal);

  ['change-pass-current', 'change-pass-new', 'change-pass-new2'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('btn-change-pass-confirm').click();
    });
  });

  document.getElementById('btn-change-pass-confirm').addEventListener('click', async () => {
    const currentPass = document.getElementById('change-pass-current').value;
    const newPass     = document.getElementById('change-pass-new').value;
    const newPass2    = document.getElementById('change-pass-new2').value;
    const errEl       = document.getElementById('change-pass-error');
    const btn         = document.getElementById('btn-change-pass-confirm');
    const spinner     = document.getElementById('change-pass-spinner');
    errEl.hidden = true;

    if (!currentPass) { showErr(errEl, 'Enter your current passphrase.'); return; }
    const newPassErr = validatePassphrase(newPass);
    if (newPassErr)              { showErr(errEl, newPassErr); return; }
    if (newPass !== newPass2)    { showErr(errEl, 'New passphrases do not match.'); return; }
    if (newPass === currentPass) { showErr(errEl, 'New passphrase must differ from current.'); return; }

    btn.disabled    = true;
    btn.textContent = 'Verifying…';
    spinner.hidden  = false;

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
      const origText = 'Change passphrase';
      btn.textContent = '✓ Done';
      btn.disabled    = false;
      setTimeout(() => { btn.textContent = origText; }, 1500);

    } catch (e) {
      showErr(errEl, e.message === 'OUTDATED_FORMAT'
        ? 'Your identity format is outdated. Please regenerate your key.'
        : 'Change failed: ' + e.message
      );
      btn.disabled    = false;
      btn.textContent = 'Change passphrase';
      spinner.hidden  = true;
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

  function showErr(el, msg) { el.textContent = msg; el.hidden = false; }

  // ─── Base64 helpers ───────────────────────────────────────────────────────────
  const toB64   = bytes => bytes.toBase64();
  const fromB64 = b64   => Uint8Array.fromBase64(b64);

  async function keyFingerprint(recipient) {
    if (!recipient) return '(no key)';
    try {
      // 64 bytes → 128 hex chars, displayed as 8 groups of 4 per line.
      const bytes = shake256(new TextEncoder().encode(recipient), 64);

      let hex = '';
      for (const b of bytes) hex += b.toString(16).padStart(2, '0');
      hex = hex.toUpperCase();
      return hex.match(/.{1,4}/g).reduce((lines, chunk, i) => {
        if (i % 8 === 0) lines.push('');
        lines[lines.length - 1] += (lines[lines.length - 1] ? ' ' : '') + chunk;
        return lines;
      }, []).join('\n');
    } catch {
      return recipient.slice(0, 16) + '…' + recipient.slice(-12);
    }
  }

  // ─── About screen ────────────────────────────────────────────────────────────

  document.getElementById('btn-back-about').addEventListener('click', showMain);

  const _aboutLinks = {
    'about-repo-link':          'https://github.com/SenseiDeElite/discord-age-encryption',
    'about-typage-link':        'https://github.com/FiloSottile/typage/blob/main/LICENSE',
    'about-rustcrypto-link':    'https://opensource.org/license/MIT',
    'about-license-link':       'https://github.com/SenseiDeElite/discord-age-encryption/blob/main/LICENSE',
  };
  Object.entries(_aboutLinks).forEach(([id, url]) => {
    document.getElementById(id).addEventListener('click', () => { chrome.tabs.create({ url }); });
  });

  function showAbout() {
    const ver = chrome.runtime.getManifest().version;
    document.getElementById('about-version').textContent = 'v' + ver;
    show('about');
  }

  // ─── Boot ────────────────────────────────────────────────────────────────────

  async function bootWithDraftCheck() {
    await boot();
    // Always check — boot() may have landed on the lock screen if the vault
    // was locked when import-helper reopened the popup.
    await checkPendingImport();
  }

  bootWithDraftCheck().catch(e => console.error('[age] popup boot error:', e));

})();
