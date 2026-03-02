pub mod ed25519;
pub mod secp256k1;
pub mod storage;
pub mod types;

use serde_json::json;
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
// wasm-bindgen exports
// ---------------------------------------------------------------------------

/// Generate an Ed25519 worker keypair.
/// Returns `{ pub_key: hex, key_id: string }`.
#[wasm_bindgen]
pub fn generate_worker_keypair() -> JsValue {
    let kp = ed25519::generate_keypair();
    let val = json!({
        "pub_key": hex::encode(&kp.pub_key),
        "key_id": kp.key_id,
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Generate a secp256k1 session keypair.
/// Returns `{ pub_key: hex, key_id: string }`.
#[wasm_bindgen]
pub fn generate_session_keypair() -> JsValue {
    let kp = secp256k1::generate_keypair();
    let val = json!({
        "pub_key": hex::encode(&kp.pub_key),
        "key_id": kp.key_id,
    });
    serde_wasm_bindgen::to_value(&val).unwrap_or(JsValue::NULL)
}

/// Sign a message with the worker (Ed25519) key.
#[wasm_bindgen]
pub fn sign_worker(message: &[u8], key_id: &str) -> Vec<u8> {
    ed25519::sign(message, key_id).0
}

/// Sign a message with the session (secp256k1) key.
#[wasm_bindgen]
pub fn sign_session(message: &[u8], key_id: &str) -> Vec<u8> {
    secp256k1::sign(message, key_id).0
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

/// Return the SHA-256 hash of this WASM module's binary.
/// Stub: returns 32 zero bytes.
#[wasm_bindgen]
pub fn get_module_hash() -> Vec<u8> {
    vec![0u8; 32]
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

    #[test]
    fn module_hash_is_32_bytes() {
        assert_eq!(get_module_hash().len(), 32);
    }
}
