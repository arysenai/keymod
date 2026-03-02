use serde::{Deserialize, Serialize};

/// A cryptographic keypair (public key + identifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub pub_key: Vec<u8>,
    pub key_id: String,
}

/// An opaque signature wrapper.
#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);
