/// secp256k1 ECDSA signing and verification using k256.

use crate::types::{KeyPair, Signature};
use k256::ecdsa::{self, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Generate a secp256k1 keypair.
/// Returns (compressed_public_key [33], private_key [32]).
pub fn generate_keypair_raw() -> (Vec<u8>, [u8; 32]) {
    let mut secret = [0u8; 32];
    // Generate random bytes until we get a valid scalar (almost always first try)
    loop {
        getrandom::getrandom(&mut secret).expect("getrandom failed");
        if SigningKey::from_bytes((&secret).into()).is_ok() {
            break;
        }
    }
    let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_encoded_point(true);
    (compressed.as_bytes().to_vec(), secret)
}

/// Generate a keypair and return it as a KeyPair with a derived key_id.
pub fn generate_keypair() -> KeyPair {
    let (pub_bytes, _priv_bytes) = generate_keypair_raw();
    let key_id = derive_key_id(&pub_bytes);
    KeyPair {
        pub_key: pub_bytes,
        key_id,
    }
}

/// Sign a message using raw private key bytes.
/// The message is SHA-256 hashed first, then signed with ECDSA.
/// Returns a 65-byte signature: [r(32) | s(32) | recovery_id(1)].
pub fn sign_raw(message: &[u8], private_key: &[u8]) -> Signature {
    let secret: [u8; 32] = private_key.try_into().expect("secp256k1 private key must be 32 bytes");
    let signing_key = SigningKey::from_bytes((&secret).into()).expect("invalid secp256k1 key");

    // SHA-256 hash the message
    let digest = Sha256::digest(message);

    let (sig, recovery_id): (ecdsa::Signature, _) = signing_key
        .sign_prehash_recoverable(&digest)
        .expect("signing failed");

    let mut sig_bytes = sig.to_bytes().to_vec(); // 64 bytes (r || s)
    sig_bytes.push(recovery_id.to_byte()); // append recovery id
    Signature(sig_bytes)
}

/// Sign a message using a key_id (looks up key from host store in WASM).
/// For native builds, this is a stub that returns a zeroed signature.
pub fn sign(message: &[u8], _key_id: &str) -> Signature {
    let _ = message;
    Signature(vec![0u8; 65])
}

/// Verify a secp256k1 ECDSA signature.
/// Accepts 64-byte (r||s) or 65-byte (r||s||v) signatures.
/// The message is SHA-256 hashed before verification.
pub fn verify(message: &[u8], signature: &[u8], pub_key: &[u8]) -> bool {
    if signature.len() < 64 || pub_key.len() != 33 {
        return false;
    }

    // Take only the first 64 bytes (r || s), ignore optional recovery byte
    let sig_bytes: &[u8] = &signature[..64];
    let Ok(sig) = ecdsa::Signature::from_slice(sig_bytes) else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(pub_key) else {
        return false;
    };

    // SHA-256 hash the message (same as sign)
    let digest = Sha256::digest(message);

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key.verify_prehash(&digest, &sig).is_ok()
}

/// Derive a key_id from a public key: hex(sha256(pub_key))[:16].
fn derive_key_id(pub_key: &[u8]) -> String {
    let hash = Sha256::digest(pub_key);
    hex::encode(&hash)[..16].to_string()
}
