pub mod storage;

pub use storage::chunker;
pub use storage::cid_util;
pub use storage::encrypt;
pub use storage::manifest;
pub use storage::pipeline;

use std::sync::Mutex;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Session keypair — generated once per WASM instance, never leaves WASM
// ---------------------------------------------------------------------------

static SESSION_SECRET: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// HKDF info string for key wrapping — must match wallet crate.
const WRAP_INFO: &[u8] = b"arysen-key-wrap-v1";

/// Initialize the storage session: generate an X25519 keypair.
///
/// The secret stays in WASM memory. Returns the session public key
/// as a 64-char hex string. The SDK passes this to the wallet's
/// `wrap_decryption_key` so it can encrypt private keys for us.
#[wasm_bindgen]
pub fn storage_init_session() -> String {
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    *SESSION_SECRET.lock().unwrap_or_else(|e| e.into_inner()) = Some(secret_bytes);

    hex::encode(public.as_bytes())
}

/// Unwrap a wrapped decryption key blob from the wallet module.
///
/// Blob format (hex-decoded): ephemeral_pub(32) | nonce(12) | ciphertext+tag(48) = 92 bytes.
/// Returns the raw X25519 private key (32 bytes), or error string.
fn unwrap_decryption_key(wrapped_hex: &str) -> Result<[u8; 32], String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let session_secret = SESSION_SECRET
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .ok_or_else(|| "storage session not initialized — call storage_init_session() first".to_string())?;

    let blob = hex::decode(wrapped_hex)
        .map_err(|e| format!("invalid wrapped key hex: {}", e))?;

    if blob.len() < 32 + 12 + 16 {
        return Err(format!("wrapped key too short: {} bytes (need >= 60)", blob.len()));
    }

    // Parse: ephemeral_pub(32) | nonce(12) | ciphertext+tag
    let eph_pub_bytes: [u8; 32] = blob[..32]
        .try_into()
        .map_err(|_| "ephemeral pubkey parse failed")?;
    let nonce_bytes: [u8; 12] = blob[32..44]
        .try_into()
        .map_err(|_| "nonce parse failed")?;
    let ciphertext = &blob[44..];

    // ECDH → shared secret → HKDF → wrapping key
    let secret = StaticSecret::from(session_secret);
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let shared = secret.diffie_hellman(&eph_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut wrapping_key = [0u8; 32];
    hk.expand(WRAP_INFO, &mut wrapping_key)
        .map_err(|e| format!("HKDF failed: {}", e))?;

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("AES key init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "key unwrap failed — wrong session key or tampered blob".to_string())?;

    if plaintext.len() != 32 {
        return Err(format!("unwrapped key wrong size: {} bytes (need 32)", plaintext.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ---------------------------------------------------------------------------
// WASM exports — thin wrappers around the pure-Rust pipeline
// ---------------------------------------------------------------------------

/// Prepare a file for encrypted upload.
///
/// Accepts raw file bytes, recipient X25519 public key (hex), chunk size,
/// and MIME type. Returns a JSON-serialized object:
/// ```json
/// {
///   "chunks": [["cid_string", [encrypted_bytes...]], ...],
///   "manifest_bytes": [u8...],
///   "root_cid": "baf...",
///   "content_hash": "hex..."
/// }
/// ```
#[wasm_bindgen]
pub fn storage_prepare_upload(
    data: &[u8],
    recipient_pubkey_hex: &str,
    chunk_size: u32,
    mime_type: &str,
) -> JsValue {
    let pubkey_bytes: [u8; 32] = match hex::decode(recipient_pubkey_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            let err = serde_json::json!({ "error": "recipient pubkey must be 64-char hex (32 bytes)" });
            return serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL);
        }
    };

    let bundle = pipeline::prepare_upload(data, &pubkey_bytes, chunk_size as usize, mime_type);

    // Serialize chunks as [[cid, [bytes...]], ...]
    let chunks_json: Vec<serde_json::Value> = bundle
        .chunks
        .iter()
        .map(|(cid, bytes)| serde_json::json!([cid, bytes]))
        .collect();

    let result = serde_json::json!({
        "chunks": chunks_json,
        "manifest_bytes": bundle.manifest_bytes,
        "root_cid": bundle.root_cid_string,
        "content_hash": hex::encode(bundle.content_hash),
    });

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Process a downloaded file: verify CIDs, decrypt, reassemble.
///
/// Accepts manifest bytes, chunks as JSON string `[["cid", [bytes...]], ...]`,
/// and a **wrapped** decryption key (from wallet's `wrap_decryption_key`).
///
/// The wrapped key is unwrapped using this module's session secret
/// (from `storage_init_session`). The raw private key never crosses
/// the WASM→JS boundary.
#[wasm_bindgen]
pub fn storage_process_download(
    manifest_bytes: &[u8],
    chunks_json: &str,
    wrapped_key_hex: &str,
) -> JsValue {
    // Unwrap the decryption key
    let secret_bytes = match unwrap_decryption_key(wrapped_key_hex) {
        Ok(k) => k,
        Err(e) => {
            let err = serde_json::json!({ "error": e });
            return serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL);
        }
    };

    // Parse chunks JSON: [["cid", [byte, byte, ...]], ...]
    let raw_chunks: Vec<(String, Vec<u8>)> = match serde_json::from_str(chunks_json) {
        Ok(c) => c,
        Err(e) => {
            let err = serde_json::json!({ "error": format!("invalid chunks JSON: {}", e) });
            return serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL);
        }
    };

    match pipeline::process_download(manifest_bytes, &raw_chunks, &secret_bytes) {
        Ok(data) => {
            let result = serde_json::json!({ "data": data });
            serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
        }
        Err(e) => {
            let err = serde_json::json!({ "error": e });
            serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Get the default chunk size (bytes).
#[wasm_bindgen]
pub fn storage_default_chunk_size() -> u32 {
    chunker::DEFAULT_CHUNK_SIZE as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Session tests mutate the global SESSION_SECRET — serialize them.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn init_session_returns_64_hex_pubkey() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pubkey = storage_init_session();
        assert_eq!(pubkey.len(), 64);
        assert!(hex::decode(&pubkey).is_ok());
    }

    #[test]
    fn init_session_different_each_call() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pub1 = storage_init_session();
        let pub2 = storage_init_session();
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn unwrap_fails_without_init() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        *SESSION_SECRET.lock().unwrap() = None;
        let result = unwrap_decryption_key("aa".repeat(92).as_str());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not initialized"));
    }

    #[test]
    fn unwrap_rejects_bad_hex() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        storage_init_session();
        let result = unwrap_decryption_key("not_hex");
        assert!(result.is_err());
    }

    #[test]
    fn unwrap_rejects_short_blob() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        storage_init_session();
        let result = unwrap_decryption_key(&hex::encode([0u8; 10]));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn full_wrap_unwrap_roundtrip() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Init storage session
        let session_pubkey_hex = storage_init_session();

        // Simulate wallet's wrap_decryption_key
        let secret_to_wrap = [42u8; 32]; // test private key

        let session_pub_bytes: [u8; 32] = hex::decode(&session_pubkey_hex)
            .unwrap()
            .try_into()
            .unwrap();

        let mut eph_bytes = [0u8; 32];
        getrandom::getrandom(&mut eph_bytes).unwrap();
        let eph_secret = StaticSecret::from(eph_bytes);
        let eph_public = PublicKey::from(&eph_secret);

        let target_pub = PublicKey::from(session_pub_bytes);
        let shared = eph_secret.diffie_hellman(&target_pub);

        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrapping_key = [0u8; 32];
        hk.expand(WRAP_INFO, &mut wrapping_key).unwrap();

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&wrapping_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, secret_to_wrap.as_ref()).unwrap();

        let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
        blob.extend_from_slice(eph_public.as_bytes());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        let wrapped_hex = hex::encode(&blob);

        // Unwrap via storage module
        let recovered = unwrap_decryption_key(&wrapped_hex).unwrap();
        assert_eq!(recovered, secret_to_wrap);
    }
}
