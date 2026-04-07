/// Storage manifest — flat list of chunk CIDs with file metadata.
///
/// Serialized as JSON for now. DAG-PB encoding can be added later
/// for full IPFS compatibility without changing the API.

use cid::Cid;
use serde::{Deserialize, Serialize};

/// Manifest describing an encrypted file upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageManifest {
    /// Ephemeral X25519 public key used for encryption (hex, 64 chars).
    pub ephemeral_pubkey: String,
    /// Ordered list of chunk CIDs (multibase strings).
    pub chunk_cids: Vec<String>,
    /// Original file size in bytes (before encryption).
    pub file_size: u64,
    /// MIME type (optional).
    #[serde(default)]
    pub mime_type: String,
    /// Chunk size used for splitting (bytes).
    pub chunk_size: u32,
}

/// Encode a manifest to bytes (JSON).
pub fn encode_manifest(manifest: &StorageManifest) -> Vec<u8> {
    serde_json::to_vec(manifest).expect("manifest serialization cannot fail")
}

/// Decode a manifest from bytes (JSON).
pub fn decode_manifest(data: &[u8]) -> Result<StorageManifest, String> {
    serde_json::from_slice(data).map_err(|e| format!("manifest decode failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> StorageManifest {
        StorageManifest {
            ephemeral_pubkey: "ab".repeat(32),
            chunk_cids: vec!["cid1".into(), "cid2".into(), "cid3".into()],
            file_size: 1_500_000,
            mime_type: "application/octet-stream".into(),
            chunk_size: 512 * 1024,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let manifest = sample_manifest();
        let encoded = encode_manifest(&manifest);
        let decoded = decode_manifest(&encoded).unwrap();
        assert_eq!(decoded.ephemeral_pubkey, manifest.ephemeral_pubkey);
        assert_eq!(decoded.chunk_cids, manifest.chunk_cids);
        assert_eq!(decoded.file_size, manifest.file_size);
        assert_eq!(decoded.mime_type, manifest.mime_type);
        assert_eq!(decoded.chunk_size, manifest.chunk_size);
    }

    #[test]
    fn decode_invalid_data_fails() {
        let result = decode_manifest(b"not valid json");
        assert!(result.is_err());
    }
}
