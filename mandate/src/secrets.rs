/// Secret vault management.
///
/// Stores encrypted secret blobs by name using AES-256-GCM.
/// Values never leave the WASM module in plaintext -- they are only injected
/// into request templates at execution time via `retrieve_secret`, which is
/// deliberately NOT exported through wasm-bindgen.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use std::collections::HashMap;

/// In-memory secret store with AES-256-GCM encryption.
///
/// Secrets are stored encrypted at rest. The encryption key is derived from
/// random bytes at vault creation time and never leaves the module.
pub struct SecretVault {
    /// name -> encrypted_value (nonce(12) || ciphertext || tag(16))
    secrets: HashMap<String, Vec<u8>>,
    /// 256-bit encryption key derived from host entropy
    encryption_key: [u8; 32],
}

impl SecretVault {
    /// Create a new vault with a randomly generated encryption key.
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("getrandom failed");
        Self {
            secrets: HashMap::new(),
            encryption_key: key,
        }
    }

    /// Create a vault with a specific key (for testing).
    #[cfg(test)]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            secrets: HashMap::new(),
            encryption_key: key,
        }
    }

    /// Store an encrypted secret by name.
    ///
    /// The `value` provided is the *plaintext* secret value. It gets encrypted
    /// with the vault's internal key before storage.
    /// Returns `true` on success. Overwrites if the name already exists.
    pub fn deposit(&mut self, name: &str, value: &[u8]) -> bool {
        match self.encrypt(value) {
            Ok(encrypted) => {
                self.secrets.insert(name.to_string(), encrypted);
                true
            }
            Err(_) => false,
        }
    }

    /// Retrieve the decrypted secret value by name.
    ///
    /// INTERNAL ONLY -- this function is NOT exported via wasm-bindgen.
    /// It is only called by the inject module during template execution.
    pub(crate) fn retrieve(&self, name: &str) -> Option<Vec<u8>> {
        let encrypted = self.secrets.get(name)?;
        self.decrypt(encrypted).ok()
    }

    /// Remove a stored secret by name.
    /// Returns `true` if the secret existed and was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    /// List stored secret names (values are never exposed).
    pub fn list_names(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// Encrypt plaintext with the vault's key using AES-256-GCM.
    /// Returns [nonce(12) || ciphertext || tag(16)].
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("cipher init error: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom error: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("encryption error: {}", e))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a blob produced by `encrypt`.
    fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext_with_nonce.len() < 12 + 16 {
            return Err("ciphertext too short".into());
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("cipher init error: {}", e))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("decryption error: {}", e))
    }
}

impl Default for SecretVault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_and_retrieve() {
        let mut vault = SecretVault::new();
        assert!(vault.deposit("api_key", b"sk-test-12345"));
        let retrieved = vault.retrieve("api_key").expect("should retrieve");
        assert_eq!(retrieved, b"sk-test-12345");
    }

    #[test]
    fn deposit_overwrite() {
        let mut vault = SecretVault::new();
        vault.deposit("key", b"value1");
        vault.deposit("key", b"value2");
        let retrieved = vault.retrieve("key").unwrap();
        assert_eq!(retrieved, b"value2");
    }

    #[test]
    fn retrieve_nonexistent_returns_none() {
        let vault = SecretVault::new();
        assert!(vault.retrieve("nonexistent").is_none());
    }

    #[test]
    fn remove_secret() {
        let mut vault = SecretVault::new();
        vault.deposit("temp", b"data");
        assert!(vault.remove("temp"));
        assert!(!vault.remove("temp"));
        assert!(vault.retrieve("temp").is_none());
    }

    #[test]
    fn list_names_only() {
        let mut vault = SecretVault::new();
        vault.deposit("key_a", b"secret_a");
        vault.deposit("key_b", b"secret_b");
        let names = vault.list_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"key_a".to_string()));
        assert!(names.contains(&"key_b".to_string()));
    }

    #[test]
    fn encrypted_at_rest() {
        let mut vault = SecretVault::new();
        vault.deposit("key", b"my_secret_value");
        // The stored bytes should NOT be the plaintext
        let raw = vault.secrets.get("key").unwrap();
        assert_ne!(raw.as_slice(), b"my_secret_value");
        // But decryption should recover it
        let decrypted = vault.retrieve("key").unwrap();
        assert_eq!(decrypted, b"my_secret_value");
    }
}
