/// Key storage with AES-256-GCM encryption, backed by host imports.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

/// Trait for opaque key storage backed by host imports.
/// Stores/retrieves encrypted blobs — no filesystem semantics.
pub trait KeyStore {
    fn read(&self, key_id: &str) -> Result<Vec<u8>, StorageError>;
    fn write(&self, key_id: &str, data: &[u8]) -> Result<(), StorageError>;
}

#[derive(Debug)]
pub enum StorageError {
    NotFound,
    WriteFailed,
    BufferTooSmall,
    HostError(i32),
    CryptoError(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "key not found"),
            StorageError::WriteFailed => write!(f, "write failed"),
            StorageError::BufferTooSmall => write!(f, "buffer too small"),
            StorageError::HostError(code) => write!(f, "host error: {code}"),
            StorageError::CryptoError(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Encrypt plaintext using AES-256-GCM.
///
/// - `key_bytes` must be exactly 32 bytes (256-bit key).
/// - Returns `[nonce(12) | ciphertext | tag(16)]`.
pub fn encrypt_key(plaintext: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    if key_bytes.len() != 32 {
        return Err(StorageError::CryptoError("key must be 32 bytes".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| StorageError::CryptoError(e.to_string()))?;

    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("getrandom failed");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| StorageError::CryptoError(e.to_string()))?;

    // Prepend the nonce: [nonce(12) | ciphertext_with_tag]
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a blob produced by `encrypt_key`.
///
/// - `ciphertext_with_nonce` is `[nonce(12) | ciphertext | tag(16)]`.
/// - `key_bytes` must be exactly 32 bytes.
/// - Returns the original plaintext.
pub fn decrypt_key(ciphertext_with_nonce: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    if key_bytes.len() != 32 {
        return Err(StorageError::CryptoError("key must be 32 bytes".into()));
    }
    if ciphertext_with_nonce.len() < 12 + 16 {
        return Err(StorageError::CryptoError(
            "ciphertext too short (need at least nonce + tag)".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| StorageError::CryptoError(e.to_string()))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| StorageError::CryptoError(e.to_string()))
}
