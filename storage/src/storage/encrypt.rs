/// Sealed-box encryption: ephemeral X25519 ECDH + HKDF + AES-256-GCM.
///
/// Per-file: one ephemeral keypair, one ECDH, one symmetric key.
/// Per-chunk: AES-256-GCM with chunk_index as nonce (deterministic, unique per key).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Result of sealing a file key for a recipient.
pub struct SealedKey {
    /// Ephemeral public key (32 bytes) — included in the manifest.
    pub ephemeral_pubkey: [u8; 32],
    /// Derived AES-256 symmetric key — used for chunk encryption.
    pub symmetric_key: [u8; 32],
}

/// HKDF info string for deriving the symmetric key.
const HKDF_INFO: &[u8] = b"arysen-storage-v1";

/// Derive a symmetric key from a shared secret using HKDF-SHA256.
fn derive_symmetric_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// Build a 12-byte nonce from a chunk index (u64 LE, zero-padded).
fn chunk_nonce(chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

/// Generate an ephemeral keypair, ECDH with recipient, derive symmetric key.
pub fn seal_file_key(recipient_pubkey: &[u8; 32]) -> SealedKey {
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("getrandom failed");
    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let recipient = PublicKey::from(*recipient_pubkey);
    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let symmetric_key = derive_symmetric_key(shared.as_bytes());

    SealedKey {
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        symmetric_key,
    }
}

/// Reverse: given recipient's secret + ephemeral pubkey, derive the same symmetric key.
pub fn unseal_file_key(recipient_secret: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*recipient_secret);
    let ephemeral = PublicKey::from(*ephemeral_pubkey);
    let shared = secret.diffie_hellman(&ephemeral);
    derive_symmetric_key(shared.as_bytes())
}

/// Encrypt a single chunk with AES-256-GCM.
/// Returns [nonce(12) | ciphertext | tag(16)].
pub fn encrypt_chunk(key: &[u8; 32], chunk_index: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key must be 32 bytes");
    let nonce_bytes = chunk_nonce(chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failed");

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt a single chunk with AES-256-GCM.
/// Input format: [nonce(12) | ciphertext | tag(16)].
pub fn decrypt_chunk(key: &[u8; 32], chunk_index: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 + 16 {
        return Err("ciphertext too short".into());
    }
    let expected_nonce = chunk_nonce(chunk_index);
    let stored_nonce = &ciphertext[..12];
    if stored_nonce != expected_nonce {
        return Err("nonce mismatch (wrong chunk index)".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(stored_nonce);
    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|e| format!("decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_same_symmetric_key() {
        let mut recipient_secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut recipient_secret_bytes).unwrap();
        let recipient_secret = StaticSecret::from(recipient_secret_bytes);
        let recipient_pubkey = PublicKey::from(&recipient_secret);

        let sealed = seal_file_key(recipient_pubkey.as_bytes());
        let unsealed = unseal_file_key(&recipient_secret_bytes, &sealed.ephemeral_pubkey);
        assert_eq!(sealed.symmetric_key, unsealed);
    }

    #[test]
    fn encrypt_decrypt_single_chunk() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let plaintext = b"hello encrypted world";
        let encrypted = encrypt_chunk(&key, 0, plaintext);
        let decrypted = decrypt_chunk(&key, 0, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_multi_chunk() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let chunks: Vec<&[u8]> = vec![b"chunk zero", b"chunk one", b"chunk two"];
        for (i, chunk) in chunks.iter().enumerate() {
            let encrypted = encrypt_chunk(&key, i as u64, chunk);
            let decrypted = decrypt_chunk(&key, i as u64, &encrypted).unwrap();
            assert_eq!(decrypted, *chunk);
        }
    }

    #[test]
    fn encryption_overhead_under_1mb() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let plaintext = vec![0xAAu8; 512 * 1024]; // 512KB
        let encrypted = encrypt_chunk(&key, 0, &plaintext);
        assert_eq!(encrypted.len(), plaintext.len() + 28);
        assert!(encrypted.len() < 1024 * 1024, "encrypted chunk must be under 1MB");
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        getrandom::getrandom(&mut key1).unwrap();
        getrandom::getrandom(&mut key2).unwrap();
        let encrypted = encrypt_chunk(&key1, 0, b"secret");
        let result = decrypt_chunk(&key2, 0, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let mut encrypted = encrypt_chunk(&key, 0, b"tamper test");
        if encrypted.len() > 13 {
            encrypted[13] ^= 0xFF;
        }
        let result = decrypt_chunk(&key, 0, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_chunk_index_fails() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let encrypted = encrypt_chunk(&key, 0, b"index test");
        let result = decrypt_chunk(&key, 1, &encrypted);
        assert!(result.is_err());
    }
}
