/// BIP-32 hardened child key derivation using HMAC-SHA512.
///
/// Uses "arysen-func" as the HMAC key for seed-to-master derivation,
/// namespaced from Bitcoin HD wallets. All derivation is hardened-only
/// (index | 0x80000000) to prevent public key derivation and key leakage.

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Derive the master key and chain code from a 32-byte seed.
/// Uses HMAC-SHA512 with key "arysen-func".
/// Returns (master_key[32], chain_code[32]).
pub fn seed_to_master(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac =
        HmacSha512::new_from_slice(b"arysen-func").expect("HMAC accepts any key length");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    (key, chain_code)
}

/// Derive a hardened child key from a parent key and chain code.
/// Index is automatically hardened (OR'd with 0x80000000).
/// Returns (child_key[32], child_chain_code[32]).
pub fn derive_hardened_child(
    parent_key: &[u8; 32],
    chain_code: &[u8; 32],
    index: u32,
) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(chain_code).expect("HMAC accepts any key length");
    // Hardened child: 0x00 || parent_key || index (big-endian, with hardened bit set)
    mac.update(&[0x00]);
    mac.update(parent_key);
    mac.update(&(index | 0x8000_0000).to_be_bytes());
    let result = mac.finalize().into_bytes();

    let mut child_key = [0u8; 32];
    let mut child_chain_code = [0u8; 32];
    child_key.copy_from_slice(&result[..32]);
    child_chain_code.copy_from_slice(&result[32..]);
    (child_key, child_chain_code)
}

/// Derive a key at a given path from a seed.
/// Each element in `path` is a hardened index.
/// Returns the final 32-byte derived key.
pub fn derive_path(seed: &[u8; 32], path: &[u32]) -> [u8; 32] {
    let (mut key, mut chain_code) = seed_to_master(seed);
    for &index in path {
        let (child_key, child_chain_code) = derive_hardened_child(&key, &chain_code, index);
        key = child_key;
        chain_code = child_chain_code;
    }
    key
}
