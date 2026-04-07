/// X25519 key operations derived from BIP-32 functionality key.
///
/// Derives X25519 keypairs at path m/0'/0'/n' where n is the rotation index.
/// StaticSecret is clamped automatically by x25519-dalek.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::bip32;

/// Derive an X25519 keypair from a BIP-32 seed at rotation index n.
/// Path: m/0'/0'/n'
/// Returns (StaticSecret, PublicKey).
pub fn derive_x25519_keypair(seed: &[u8; 32], rotation_index: u32) -> (StaticSecret, PublicKey) {
    let derived = bip32::derive_path(seed, &[0, 0, rotation_index]);
    let secret = StaticSecret::from(derived);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Encode an X25519 public key as a hex string (64 chars).
pub fn x25519_public_key_hex(pub_key: &PublicKey) -> String {
    hex::encode(pub_key.as_bytes())
}
