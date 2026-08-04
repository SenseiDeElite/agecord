/*
 * This source code is licensed under the MIT License.
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/rustcrypto-wasm/LICENSE
 */

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// ─── XChaCha20Poly1305 ────────────────────────────────────────────────────────

use chacha20poly1305::{
    aead::{Aead, Generate as AeadGenerate, KeyInit},
    XChaCha20Poly1305, XNonce,
};

/// Encrypt with XChaCha20Poly1305.
/// `key`: 32 bytes. Returns `nonce (24 bytes) || ciphertext+tag`.
#[wasm_bindgen]
pub fn xchacha20poly1305_encrypt(key: Vec<u8>, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = Zeroizing::new(key);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| JsError::new("xchacha20poly1305_encrypt: key must be exactly 32 bytes"))?;
    drop(key); // raw key bytes are fully expanded into `cipher` now — scrub them immediately
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| JsError::new("xchacha20poly1305_encrypt: encryption failed"))?;
    drop(cipher); // zero the expanded key/keystream state before touching non-secret output bytes
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt with XChaCha20Poly1305.
/// `key`: 32 bytes. `data`: `nonce (24 bytes) || ciphertext+tag`.
#[wasm_bindgen]
pub fn xchacha20poly1305_decrypt(key: Vec<u8>, data: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = Zeroizing::new(key);
    if data.len() < 24 {
        return Err(JsError::new(
            "xchacha20poly1305_decrypt: data too short to contain a nonce",
        ));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| JsError::new("xchacha20poly1305_decrypt: key must be exactly 32 bytes"))?;
    drop(key); // same as above — expanded into `cipher`, no longer needed
    let nonce = XNonce::try_from(&data[..24])
        .map_err(|_| JsError::new("xchacha20poly1305_decrypt: invalid nonce length"))?;
    let result = cipher
        .decrypt(&nonce, &data[24..])
        .map_err(|_| JsError::new("xchacha20poly1305_decrypt: decryption failed (wrong key or corrupted data)"));
    drop(cipher); // scrub before returning plaintext to caller
    result
}

// ─── SHAKE256 ─────────────────────────────────────────────────────────────────

use shake::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Hash `input` with SHAKE256, returning `output_len` bytes.
#[wasm_bindgen]
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof(); // consumes `hasher`, no lingering copy
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

// ─── Argon2id ─────────────────────────────────────────────────────────────────

use argon2::{Algorithm, Argon2, Params, Version};

/// Derive a key with Argon2id (raw KDF, not PHC string).
/// - `m_cost`: memory in KiB (e.g. 65536 = 64 MiB)
/// - `t_cost`: iterations (e.g. 3)
/// - `p_cost`: parallelism (e.g. 4)
/// - `output_len`: desired output length in bytes
#[wasm_bindgen]
pub fn argon2id(
    password: Vec<u8>,
    salt: Vec<u8>,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
) -> Result<Vec<u8>, JsError> {
    let password = Zeroizing::new(password);
    let salt = Zeroizing::new(salt);
    let params = Params::new(m_cost, t_cost, p_cost, Some(output_len))
        .map_err(|e| JsError::new(&format!("argon2id: invalid params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; output_len];
    let result = argon2
        .hash_password_into(&password, &salt, &mut out)
        .map_err(|e| JsError::new(&format!("argon2id: hashing failed: {e}")));
    drop(password);
    drop(salt); // hashing is done with these; zero them now via Zeroizing's Drop
    result?;
    Ok(out)
}

// ─── ML-DSA-87 ────────────────────────────────────────────────────────────────
// Key sizes (ml-dsa 0.1.1 actual values):
//   Seed (canonical private key): 32 bytes
//   VerifyingKey:                 2592 bytes
//   Signature:                    4627 bytes

use ml_dsa::{
    KeyExport, Keypair, MlDsa87, Signature, SignatureEncoding,
    SigningKey, Signer, VerifyingKey, Verifier,
};

/// Generate an ML-DSA-87 keypair.
/// Returns `seed (32 bytes) || verifying_key (2592 bytes)` — 2624 bytes total.
#[wasm_bindgen]
pub fn ml_dsa87_keygen() -> Vec<u8> {
    let sk = SigningKey::<MlDsa87>::generate();
    let seed = sk.to_bytes();
    let vk = sk.verifying_key().to_bytes();
    drop(sk); // zero the expanded lattice private-key state now that both outputs are copied out
    let mut out = Vec::with_capacity(32 + vk.len());
    out.extend_from_slice(&seed);
    out.extend_from_slice(&vk);
    out
}

/// Sign a message with ML-DSA-87.
/// `seed`: 32 bytes. Returns the signature — 4627 bytes.
#[wasm_bindgen]
pub fn ml_dsa87_sign(seed: Vec<u8>, message: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed = Zeroizing::new(seed);
    let seed_arr: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("ml_dsa87_sign: seed must be exactly 32 bytes"))?;
    let sk = SigningKey::<MlDsa87>::from_seed(seed_arr.into());
    drop(seed); // seed_arr's borrow ends here (unused after); scrub the raw seed early
    let sig = sk.sign(message);
    drop(sk); // scrub expanded key state before allocating/returning the signature bytes
    Ok(sig.to_bytes().to_vec())
}

/// Verify an ML-DSA-87 signature.
/// `verifying_key`: 2592 bytes. `signature`: 4627 bytes.
/// Returns `true` if valid, `false` for any error or invalid signature.
#[wasm_bindgen]
pub fn ml_dsa87_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let vk_arr: &[u8; 2592] = match verifying_key.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: &[u8; 4627] = match signature.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(vk_arr.into());
    let sig = match Signature::<MlDsa87>::decode(sig_arr.into()) {
        Some(s) => s,
        None => return false,
    };
    vk.verify(message, &sig).is_ok()
}

/// Derive the verifying key from a 32-byte seed.
/// `seed`: 32 bytes. Returns the verifying key — 2592 bytes.
#[wasm_bindgen]
pub fn ml_dsa87_verifying_key_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let seed = Zeroizing::new(seed);
    let seed_arr: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("ml_dsa87_verifying_key_from_seed: seed must be exactly 32 bytes"))?;
    let sk = SigningKey::<MlDsa87>::from_seed(seed_arr.into());
    drop(seed); // same reasoning as ml_dsa87_sign
    let vk = sk.verifying_key().to_bytes();
    drop(sk);
    Ok(vk.to_vec())
}
