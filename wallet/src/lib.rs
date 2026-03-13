pub mod ed25519;
pub mod secp256k1;
pub mod storage;
pub mod types;

use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Host imports — provided by the WASM runtime (Wassette / Node.js host)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn key_store_read(key_id: *const u8, key_id_len: u32, buf: *mut u8, buf_len: u32) -> i32;
    fn key_store_write(key_id: *const u8, key_id_len: u32, data: *const u8, data_len: u32) -> i32;
    fn get_random_bytes(buf: *mut u8, len: u32) -> i32;
    fn get_time() -> u64;
}

// Native stubs for `cargo test` (not compiled into WASM)
#[cfg(not(target_arch = "wasm32"))]
mod host_stubs {
    #[no_mangle]
    pub extern "C" fn key_store_read(
        _key_id: *const u8,
        _key_id_len: u32,
        _buf: *mut u8,
        _buf_len: u32,
    ) -> i32 {
        -1 // not found
    }

    #[no_mangle]
    pub extern "C" fn key_store_write(
        _key_id: *const u8,
        _key_id_len: u32,
        _data: *const u8,
        _data_len: u32,
    ) -> i32 {
        0 // success
    }

    #[no_mangle]
    pub extern "C" fn get_random_bytes(_buf: *mut u8, _len: u32) -> i32 {
        0 // success (all zeros)
    }

    #[no_mangle]
    pub extern "C" fn get_time() -> u64 {
        0 // epoch
    }
}

// ---------------------------------------------------------------------------
// In-memory key store — holds private keys for the lifetime of the WASM instance
// ---------------------------------------------------------------------------

static KEY_STORE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

fn store_private_key(key_id: &str, private_key: &[u8]) {
    let mut guard = KEY_STORE.lock().unwrap_or_else(|e| e.into_inner());
    let store = guard.get_or_insert_with(HashMap::new);
    store.insert(key_id.to_string(), private_key.to_vec());
}

fn load_private_key(key_id: &str) -> Option<Vec<u8>> {
    let guard = KEY_STORE.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref()?.get(key_id).cloned()
}

// ---------------------------------------------------------------------------
// Internal functions (testable without wasm_bindgen)
// ---------------------------------------------------------------------------

/// Generate an Ed25519 worker keypair and store the private key.
fn generate_worker_internal() -> (Vec<u8>, String) {
    let (pub_bytes, priv_bytes) = ed25519::generate_keypair_raw();
    let key_id = ed25519::derive_key_id(&pub_bytes);
    store_private_key(&key_id, &priv_bytes);
    (pub_bytes.to_vec(), key_id)
}

/// Generate a secp256k1 session keypair and store the private key.
fn generate_session_internal() -> (Vec<u8>, String) {
    let (pub_bytes, priv_bytes) = secp256k1::generate_keypair_raw();
    let key_id = secp256k1::derive_key_id(&pub_bytes);
    store_private_key(&key_id, &priv_bytes);
    (pub_bytes, key_id)
}

/// Sign with Ed25519 worker key from the key store.
fn sign_worker_internal(message: &[u8], key_id: &str) -> Option<Vec<u8>> {
    let priv_key = load_private_key(key_id)?;
    Some(ed25519::sign_raw(message, &priv_key).0)
}

/// Sign with secp256k1 session key from the key store.
fn sign_session_internal(message: &[u8], key_id: &str) -> Option<Vec<u8>> {
    let priv_key = load_private_key(key_id)?;
    Some(secp256k1::sign_raw(message, &priv_key).0)
}

// ---------------------------------------------------------------------------
// wasm-bindgen exports
// ---------------------------------------------------------------------------

/// Generate an Ed25519 worker keypair.
/// Returns `{ pub_key: hex, key_id: string }`.
#[wasm_bindgen]
pub fn generate_worker_keypair() -> JsValue {
    let (pub_bytes, key_id) = generate_worker_internal();
    let val = json!({
        "pub_key": hex::encode(&pub_bytes),
        "key_id": key_id,
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Generate an Ed25519 worker keypair and return the private key.
/// Returns `{ pub_key: hex, key_id: string, private_key: hex }`.
/// Used internally by the SDK to pass the key to the mandate module.
#[wasm_bindgen]
pub fn generate_worker_keypair_with_secret() -> JsValue {
    let (pub_bytes, priv_bytes) = ed25519::generate_keypair_raw();
    let key_id = ed25519::derive_key_id(&pub_bytes);
    store_private_key(&key_id, &priv_bytes);
    let val = json!({
        "pub_key": hex::encode(&pub_bytes),
        "key_id": key_id,
        "private_key": hex::encode(&priv_bytes),
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Generate a secp256k1 session keypair.
/// Returns `{ pub_key: hex, key_id: string }`.
#[wasm_bindgen]
pub fn generate_session_keypair() -> JsValue {
    let (pub_bytes, key_id) = generate_session_internal();
    let val = json!({
        "pub_key": hex::encode(&pub_bytes),
        "key_id": key_id,
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Generate a secp256k1 session keypair and return the private key.
/// Returns `{ pub_key: hex, key_id: string, private_key: hex }`.
#[wasm_bindgen]
pub fn generate_session_keypair_with_secret() -> JsValue {
    let (pub_bytes, priv_bytes) = secp256k1::generate_keypair_raw();
    let key_id = secp256k1::derive_key_id(&pub_bytes);
    store_private_key(&key_id, &priv_bytes);
    let val = json!({
        "pub_key": hex::encode(&pub_bytes),
        "key_id": key_id,
        "private_key": hex::encode(&priv_bytes),
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Sign a message with the worker (Ed25519) key.
/// Returns the real signature if the key is in the store, zeros otherwise.
#[wasm_bindgen]
pub fn sign_worker(message: &[u8], key_id: &str) -> Vec<u8> {
    sign_worker_internal(message, key_id).unwrap_or_else(|| vec![0u8; 64])
}

/// Sign a message with the session (secp256k1) key.
/// Returns the real signature if the key is in the store, zeros otherwise.
#[wasm_bindgen]
pub fn sign_session(message: &[u8], key_id: &str) -> Vec<u8> {
    sign_session_internal(message, key_id).unwrap_or_else(|| vec![0u8; 65])
}

/// Verify an Ed25519 signature.
#[wasm_bindgen]
pub fn verify_worker(message: &[u8], signature: &[u8], pub_key: &[u8]) -> bool {
    ed25519::verify(message, signature, pub_key)
}

/// Verify a secp256k1 signature.
#[wasm_bindgen]
pub fn verify_session(message: &[u8], signature: &[u8], pub_key: &[u8]) -> bool {
    secp256k1::verify(message, signature, pub_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Ed25519 roundtrip ---

    #[test]
    fn ed25519_generate_returns_32_byte_pubkey() {
        let kp = ed25519::generate_keypair();
        assert_eq!(kp.pub_key.len(), 32);
        assert!(!kp.key_id.is_empty());
        assert_eq!(kp.key_id.len(), 16); // hex(sha256(pk))[:16]
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let (pub_key, priv_key) = ed25519::generate_keypair_raw();
        let message = b"Hello, Ed25519!";
        let sig = ed25519::sign_raw(message, &priv_key);
        assert_eq!(sig.0.len(), 64);
        assert!(ed25519::verify(message, &sig.0, &pub_key));
    }

    #[test]
    fn ed25519_wrong_message_fails() {
        let (pub_key, priv_key) = ed25519::generate_keypair_raw();
        let sig = ed25519::sign_raw(b"original", &priv_key);
        assert!(!ed25519::verify(b"tampered", &sig.0, &pub_key));
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let (_pub_key1, priv_key1) = ed25519::generate_keypair_raw();
        let (pub_key2, _priv_key2) = ed25519::generate_keypair_raw();
        let sig = ed25519::sign_raw(b"test", &priv_key1);
        assert!(!ed25519::verify(b"test", &sig.0, &pub_key2));
    }

    // --- secp256k1 roundtrip ---

    #[test]
    fn secp256k1_generate_returns_33_byte_pubkey() {
        let kp = secp256k1::generate_keypair();
        assert_eq!(kp.pub_key.len(), 33);
        assert!(!kp.key_id.is_empty());
        assert_eq!(kp.key_id.len(), 16);
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let (pub_key, priv_key) = secp256k1::generate_keypair_raw();
        let message = b"Hello, secp256k1!";
        let sig = secp256k1::sign_raw(message, &priv_key);
        assert_eq!(sig.0.len(), 65); // r(32) + s(32) + v(1)
        assert!(secp256k1::verify(message, &sig.0, &pub_key));
    }

    #[test]
    fn secp256k1_wrong_message_fails() {
        let (pub_key, priv_key) = secp256k1::generate_keypair_raw();
        let sig = secp256k1::sign_raw(b"original", &priv_key);
        assert!(!secp256k1::verify(b"tampered", &sig.0, &pub_key));
    }

    #[test]
    fn secp256k1_wrong_key_fails() {
        let (_pub_key1, priv_key1) = secp256k1::generate_keypair_raw();
        let (pub_key2, _priv_key2) = secp256k1::generate_keypair_raw();
        let sig = secp256k1::sign_raw(b"test", &priv_key1);
        assert!(!secp256k1::verify(b"test", &sig.0, &pub_key2));
    }

    // --- AES-256-GCM roundtrip ---

    #[test]
    fn aes_gcm_encrypt_decrypt_roundtrip() {
        let plaintext = b"secret private key material";
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();

        let encrypted = storage::encrypt_key(plaintext, &key).unwrap();
        // encrypted = nonce(12) + ciphertext + tag(16)
        assert!(encrypted.len() >= 12 + plaintext.len() + 16);

        let decrypted = storage::decrypt_key(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let plaintext = b"secret data";
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        getrandom::getrandom(&mut key1).unwrap();
        getrandom::getrandom(&mut key2).unwrap();

        let encrypted = storage::encrypt_key(plaintext, &key1).unwrap();
        let result = storage::decrypt_key(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let plaintext = b"secret data";
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();

        let mut encrypted = storage::encrypt_key(plaintext, &key).unwrap();
        // Tamper with a ciphertext byte (after the 12-byte nonce)
        if encrypted.len() > 13 {
            encrypted[13] ^= 0xff;
        }
        let result = storage::decrypt_key(&encrypted, &key);
        assert!(result.is_err());
    }

    // --- Cross-key rejection ---

    #[test]
    fn ed25519_sig_fails_secp256k1_verify() {
        let (_ed_pub, ed_priv) = ed25519::generate_keypair_raw();
        let (secp_pub, _secp_priv) = secp256k1::generate_keypair_raw();
        let message = b"cross-key test";
        let ed_sig = ed25519::sign_raw(message, &ed_priv);
        // Ed25519 signature (64 bytes) should not verify as secp256k1
        assert!(!secp256k1::verify(message, &ed_sig.0, &secp_pub));
    }

    #[test]
    fn secp256k1_sig_fails_ed25519_verify() {
        let (ed_pub, _ed_priv) = ed25519::generate_keypair_raw();
        let (_secp_pub, secp_priv) = secp256k1::generate_keypair_raw();
        let message = b"cross-key test";
        let secp_sig = secp256k1::sign_raw(message, &secp_priv);
        // secp256k1 signature (65 bytes) should not verify as Ed25519
        assert!(!ed25519::verify(message, &secp_sig.0, &ed_pub));
    }

    // --- Key store roundtrip tests ---

    #[test]
    fn worker_sign_verify_via_keystore() {
        let (pub_bytes, key_id) = generate_worker_internal();
        let message = b"hello from key store";
        let sig = sign_worker_internal(message, &key_id).expect("key should be in store");
        assert_eq!(sig.len(), 64);
        assert!(ed25519::verify(message, &sig, &pub_bytes));
        // Wrong message fails
        assert!(!ed25519::verify(b"wrong", &sig, &pub_bytes));
    }

    #[test]
    fn session_sign_verify_via_keystore() {
        let (pub_bytes, key_id) = generate_session_internal();
        let message = b"hello from key store";
        let sig = sign_session_internal(message, &key_id).expect("key should be in store");
        assert_eq!(sig.len(), 65);
        assert!(secp256k1::verify(message, &sig, &pub_bytes));
        // Wrong message fails
        assert!(!secp256k1::verify(b"wrong", &sig, &pub_bytes));
    }

    #[test]
    fn sign_with_unknown_key_returns_none() {
        assert!(sign_worker_internal(b"test", "nonexistent_key_id").is_none());
        assert!(sign_session_internal(b"test", "nonexistent_key_id").is_none());
    }

    // --- Legacy tests (kept for backwards compatibility) ---

    #[test]
    fn worker_keypair_has_32_byte_pubkey() {
        let kp = ed25519::generate_keypair();
        assert_eq!(kp.pub_key.len(), 32);
        assert!(!kp.key_id.is_empty());
    }

    #[test]
    fn session_keypair_has_33_byte_pubkey() {
        let kp = secp256k1::generate_keypair();
        assert_eq!(kp.pub_key.len(), 33);
        assert!(!kp.key_id.is_empty());
    }

}
