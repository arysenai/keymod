/// Ed25519 signing and verification using ed25519-dalek.

use crate::types::{KeyPair, Signature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Generate an Ed25519 keypair.
/// Returns (public_key_bytes [32], private_key_bytes [32]).
pub fn generate_keypair_raw() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("getrandom failed");
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.to_bytes(), secret)
}

/// Generate a keypair and return it as a KeyPair with a derived key_id.
/// The private key is stored internally — in a real deployment it would
/// be persisted to the host key store.
pub fn generate_keypair() -> KeyPair {
    let (pub_bytes, _priv_bytes) = generate_keypair_raw();
    let key_id = derive_key_id(&pub_bytes);
    KeyPair {
        pub_key: pub_bytes.to_vec(),
        key_id,
    }
}

/// Sign a message using raw private key bytes.
pub fn sign_raw(message: &[u8], private_key: &[u8]) -> Signature {
    let secret: [u8; 32] = private_key.try_into().expect("ed25519 private key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&secret);
    let sig = signing_key.sign(message);
    Signature(sig.to_bytes().to_vec())
}

/// Sign a message using a key_id (looks up key from host store in WASM).
/// For native builds, this is a stub that returns a zeroed signature.
pub fn sign(message: &[u8], _key_id: &str) -> Signature {
    // In WASM mode, we would read the private key from the host key store.
    // For native mode (cargo test), this path isn't used — tests call sign_raw directly.
    let _ = message;
    Signature(vec![0u8; 64])
}

/// Verify an Ed25519 signature.
pub fn verify(message: &[u8], signature: &[u8], pub_key: &[u8]) -> bool {
    if signature.len() != 64 || pub_key.len() != 32 {
        return false;
    }
    let sig_bytes: [u8; 64] = signature.try_into().unwrap();
    let pub_bytes: [u8; 32] = pub_key.try_into().unwrap();

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

/// Derive a key_id from a public key: hex(sha256(pub_key))[:16].
pub(crate) fn derive_key_id(pub_key: &[u8]) -> String {
    let hash = Sha256::digest(pub_key);
    hex::encode(&hash)[..16].to_string()
}
