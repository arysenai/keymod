/// Secret vault management.
///
/// Stores encrypted secret blobs by name using AES-256-GCM.
/// Values never leave the WASM module in plaintext -- they are only injected
/// into request templates at execution time via `retrieve_secret`, which is
/// deliberately NOT exported through wasm-bindgen.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

/// Persistent secret store with AES-256-GCM encryption backed by platform keychain.
///
/// Secrets are stored encrypted in the platform keychain (macOS Keychain, Windows DPAPI,
/// Linux libsecret) via host imports. The master encryption key is lazily loaded from
/// keychain and cached in memory for the vault's lifetime.
pub struct SecretVault {
    /// Cached 256-bit master key (lazy-loaded from keychain)
    master_key: Option<[u8; 32]>,
}

impl SecretVault {
    /// Create a new vault. Master key is lazy-loaded on first use.
    pub fn new() -> Self {
        Self { master_key: None }
    }

    /// Create a vault with a specific key (for testing).
    #[cfg(test)]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            master_key: Some(key),
        }
    }

    /// Ensure master key is loaded/generated.
    /// Tries to load from keychain first; if not found, generates and persists a new one.
    fn ensure_master_key(&mut self) -> Result<(), String> {
        if self.master_key.is_some() {
            return Ok(());
        }

        // Try loading from keystore
        if let Some(data) = arysen_wallet::host_key_store_read("arysen_secrets_master") {
            if data.len() != 32 {
                return Err(format!("secrets master key has wrong length: {}", data.len()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            self.master_key = Some(key);
            return Ok(());
        }

        // First boot: generate and persist
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| format!("getrandom failed: {}", e))?;
        arysen_wallet::host_key_store_write("arysen_secrets_master", &key)?;
        self.master_key = Some(key);
        Ok(())
    }

    /// Load the secret names index from keychain.
    /// Returns empty vec if index doesn't exist or is corrupted.
    fn load_secret_names_index() -> Vec<String> {
        let data = match arysen_wallet::host_key_store_read("arysen_secrets_index") {
            Some(d) => d,
            None => return Vec::new(),
        };

        match String::from_utf8(data) {
            Ok(json_str) => serde_json::from_str(&json_str).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// Save the secret names index to keychain.
    fn save_secret_names_index(names: &[String]) -> Result<(), String> {
        let json =
            serde_json::to_string(names).map_err(|e| format!("failed to serialize index: {}", e))?;
        arysen_wallet::host_key_store_write("arysen_secrets_index", json.as_bytes())
    }

    /// Add a secret name to the index (idempotent).
    fn add_to_index(name: &str) -> Result<(), String> {
        let mut names = Self::load_secret_names_index();
        if !names.contains(&name.to_string()) {
            names.push(name.to_string());
            Self::save_secret_names_index(&names)?;
        }
        Ok(())
    }

    /// Remove a secret name from the index.
    /// Returns Ok(true) if the name was found and removed, Ok(false) if not found.
    fn remove_from_index(name: &str) -> Result<bool, String> {
        let mut names = Self::load_secret_names_index();
        let original_len = names.len();
        names.retain(|n| n != name);
        let removed = names.len() != original_len;
        Self::save_secret_names_index(&names)?;
        Ok(removed)
    }

    /// Store an encrypted secret by name.
    ///
    /// The `value` provided is the *plaintext* secret value. It gets encrypted
    /// with the vault's master key before storage in the platform keychain.
    /// Returns `true` on success. Overwrites if the name already exists.
    pub fn deposit(&mut self, name: &str, value: &[u8]) -> bool {
        // 1. Ensure master key loaded/generated
        if self.ensure_master_key().is_err() {
            return false;
        }
        let master_key = self.master_key.as_ref().unwrap();

        // 2. Encrypt the secret
        let encrypted = match self.encrypt(value, master_key) {
            Ok(enc) => enc,
            Err(_) => return false,
        };

        // 3. Store in keystore
        let key_id = format!("arysen_secrets:{}", name);
        if arysen_wallet::host_key_store_write(&key_id, &encrypted).is_err() {
            return false;
        }

        // 4. Update index
        if Self::add_to_index(name).is_err() {
            return false;
        }

        true
    }

    /// Retrieve the decrypted secret value by name.
    ///
    /// INTERNAL ONLY -- this function is NOT exported via wasm-bindgen.
    /// It is only called by the inject module during template execution.
    /// Returns None if the secret is not in the index (even if it exists in keystore).
    pub(crate) fn retrieve(&mut self, name: &str) -> Option<Vec<u8>> {
        // Check if the secret is in the index first
        let names = Self::load_secret_names_index();
        if !names.contains(&name.to_string()) {
            return None;
        }

        self.ensure_master_key().ok()?;
        let master_key = self.master_key.as_ref()?;

        let key_id = format!("arysen_secrets:{}", name);
        let encrypted = arysen_wallet::host_key_store_read(&key_id)?;

        self.decrypt(&encrypted, master_key).ok()
    }

    /// Remove a stored secret by name.
    /// Returns `true` if the secret existed and was removed from the index.
    /// Note: The keystore entry remains but becomes unlisted.
    pub fn remove(&mut self, name: &str) -> bool {
        Self::remove_from_index(name).unwrap_or(false)
    }

    /// List stored secret names (values are never exposed).
    pub fn list_names(&self) -> Vec<String> {
        Self::load_secret_names_index()
    }

    /// Encrypt plaintext with the provided key using AES-256-GCM.
    /// Returns [nonce(12) || ciphertext || tag(16)].
    fn encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init error: {}", e))?;

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
    fn decrypt(&self, ciphertext_with_nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        if ciphertext_with_nonce.len() < 12 + 16 {
            return Err("ciphertext too short".into());
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init error: {}", e))?;

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

    /// Clear test state to ensure test isolation
    fn clear_test_state() {
        // Clear the index
        let _ = arysen_wallet::host_key_store_write("arysen_secrets_index", b"[]");
    }

    #[test]
    fn deposit_and_retrieve() {
        clear_test_state();
        let mut vault = SecretVault::new();
        assert!(vault.deposit("api_key", b"sk-test-12345"), "deposit failed");
        // Check index
        let names = vault.list_names();
        assert!(names.contains(&"api_key".to_string()), "api_key not in index: {:?}", names);
        let retrieved = vault.retrieve("api_key").expect("should retrieve");
        assert_eq!(retrieved, b"sk-test-12345");
    }

    #[test]
    fn deposit_overwrite() {
        clear_test_state();
        let mut vault = SecretVault::new();
        vault.deposit("overwrite_key", b"value1");
        vault.deposit("overwrite_key", b"value2");
        let retrieved = vault.retrieve("overwrite_key").unwrap();
        assert_eq!(retrieved, b"value2");
    }

    #[test]
    fn retrieve_nonexistent_returns_none() {
        clear_test_state();
        let mut vault = SecretVault::new();
        assert!(vault.retrieve("nonexistent").is_none());
    }

    #[test]
    fn remove_secret() {
        clear_test_state();
        let mut vault = SecretVault::new();
        vault.deposit("temp", b"data");
        assert!(vault.remove("temp"));
        assert!(!vault.remove("temp"));
        assert!(vault.retrieve("temp").is_none());
    }

    #[test]
    fn list_names_only() {
        clear_test_state();
        let mut vault = SecretVault::new();
        assert!(vault.deposit("list_key_a", b"secret_a"), "deposit list_key_a failed");
        assert!(vault.deposit("list_key_b", b"secret_b"), "deposit list_key_b failed");
        let names = vault.list_names();
        assert_eq!(names.len(), 2, "expected 2 names, got {:?}", names);
        assert!(names.contains(&"list_key_a".to_string()));
        assert!(names.contains(&"list_key_b".to_string()));
    }

    #[test]
    fn encrypted_at_rest() {
        clear_test_state();
        let mut vault = SecretVault::new();
        vault.deposit("encrypted_key", b"my_secret_value");

        // Read raw encrypted data from keystore
        let raw = arysen_wallet::host_key_store_read("arysen_secrets:encrypted_key").unwrap();
        // The stored bytes should NOT be the plaintext
        assert_ne!(raw.as_slice(), b"my_secret_value");
        // But decryption via retrieve should recover it
        let decrypted = vault.retrieve("encrypted_key").unwrap();
        assert_eq!(decrypted, b"my_secret_value");
    }

    #[test]
    fn secrets_survive_vault_reload() {
        clear_test_state();

        let mut vault1 = SecretVault::new();
        assert!(vault1.deposit("TEST_KEY", b"test_value"));

        // Simulate restart: create new vault instance
        let mut vault2 = SecretVault::new();
        let retrieved = vault2.retrieve("TEST_KEY").expect("should load persisted secret");
        assert_eq!(retrieved, b"test_value");

        // Cleanup
        vault2.remove("TEST_KEY");
    }
}
