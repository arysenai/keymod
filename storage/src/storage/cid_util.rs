/// CID computation — CIDv1 with SHA-256 multihash.

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

/// Raw multicodec (0x55) — for encrypted chunk blobs.
pub const RAW_CODEC: u64 = 0x55;

/// DAG-PB multicodec (0x70) — for the manifest.
pub const DAG_PB_CODEC: u64 = 0x70;

fn compute_cid_with_codec(data: &[u8], codec: u64) -> Cid {
    let hash = Code::Sha2_256.digest(data);
    Cid::new_v1(codec, hash)
}

/// Compute a CIDv1 for raw data (SHA-256, raw codec).
pub fn compute_cid(data: &[u8]) -> Cid {
    compute_cid_with_codec(data, RAW_CODEC)
}

/// Compute a CIDv1 for a DAG-PB encoded manifest.
pub fn compute_dag_pb_cid(data: &[u8]) -> Cid {
    compute_cid_with_codec(data, DAG_PB_CODEC)
}

/// Encode a CID to bytes.
pub fn cid_to_bytes(cid: &Cid) -> Vec<u8> {
    cid.to_bytes()
}

/// Encode a CID to a string (default multibase from the cid crate).
pub fn cid_to_string(cid: &Cid) -> String {
    cid.to_string()
}

/// Extract the raw SHA-256 digest (32 bytes) from a CID.
/// This is what goes on-chain as bytes32.
pub fn cid_digest(cid: &Cid) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(cid.hash().digest());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_is_v1_sha256_raw() {
        let cid = compute_cid(b"hello world");
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), RAW_CODEC);
    }

    #[test]
    fn cid_deterministic() {
        let a = compute_cid(b"same data");
        let b = compute_cid(b"same data");
        assert_eq!(a, b);
    }

    #[test]
    fn cid_different_data_different_cid() {
        let a = compute_cid(b"data A");
        let b = compute_cid(b"data B");
        assert_ne!(a, b);
    }

    #[test]
    fn cid_bytes_roundtrip() {
        let cid = compute_cid(b"roundtrip test");
        let bytes = cid_to_bytes(&cid);
        let parsed = Cid::try_from(bytes.as_slice()).expect("should parse CID from bytes");
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_string_not_empty() {
        let cid = compute_cid(b"string test");
        let s = cid_to_string(&cid);
        assert!(!s.is_empty());
    }

    #[test]
    fn cid_digest_is_32_bytes() {
        let cid = compute_cid(b"digest test");
        let digest = cid_digest(&cid);
        assert_eq!(digest.len(), 32);
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"digest test");
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn dag_pb_cid_uses_correct_codec() {
        let cid = compute_dag_pb_cid(b"manifest data");
        assert_eq!(cid.codec(), DAG_PB_CODEC);
    }
}
