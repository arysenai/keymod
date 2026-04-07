/// End-to-end pipeline: chunk → encrypt → CID → manifest, and reverse.
///
/// This module ties together chunker, encrypt, cid_util, and manifest
/// into a single prepare/process API. No I/O — returns data structures
/// that the caller (mandate or SDK) uploads/downloads.

use crate::storage::{chunker, cid_util, encrypt, manifest::StorageManifest};

/// A prepared upload: encrypted chunks with CIDs + manifest.
pub struct UploadBundle {
    /// Encrypted chunks, each keyed by its CID string.
    pub chunks: Vec<(String, Vec<u8>)>,
    /// Encoded manifest bytes.
    pub manifest_bytes: Vec<u8>,
    /// Root CID of the manifest.
    pub root_cid_string: String,
    /// Raw SHA-256 digest of the manifest (for on-chain bytes32).
    pub content_hash: [u8; 32],
}

/// Prepare a file for upload: chunk, encrypt, compute CIDs, build manifest.
///
/// - `data`: raw file bytes
/// - `recipient_pubkey`: X25519 public key (32 bytes)
/// - `chunk_size`: bytes per chunk (default 512KB)
/// - `mime_type`: optional MIME type
pub fn prepare_upload(
    data: &[u8],
    recipient_pubkey: &[u8; 32],
    chunk_size: usize,
    mime_type: &str,
) -> UploadBundle {
    let sealed = encrypt::seal_file_key(recipient_pubkey);

    let raw_chunks = chunker::chunk_file(data, chunk_size);
    let mut encrypted_chunks = Vec::with_capacity(raw_chunks.len());
    let mut chunk_cid_strings = Vec::with_capacity(raw_chunks.len());

    for (i, chunk) in raw_chunks.iter().enumerate() {
        let encrypted = encrypt::encrypt_chunk(&sealed.symmetric_key, i as u64, chunk);
        let cid = cid_util::compute_cid(&encrypted);
        let cid_str = cid_util::cid_to_string(&cid);
        chunk_cid_strings.push(cid_str.clone());
        encrypted_chunks.push((cid_str, encrypted));
    }

    let manifest = StorageManifest {
        ephemeral_pubkey: hex::encode(sealed.ephemeral_pubkey),
        chunk_cids: chunk_cid_strings,
        file_size: data.len() as u64,
        mime_type: mime_type.to_string(),
        chunk_size: chunk_size as u32,
    };

    let manifest_bytes = crate::storage::manifest::encode_manifest(&manifest);
    let manifest_cid = cid_util::compute_dag_pb_cid(&manifest_bytes);
    let root_cid_string = cid_util::cid_to_string(&manifest_cid);
    let content_hash = cid_util::cid_digest(&manifest_cid);

    UploadBundle {
        chunks: encrypted_chunks,
        manifest_bytes,
        root_cid_string,
        content_hash,
    }
}

/// Process a download: verify chunk CIDs, decrypt, reassemble.
///
/// - `manifest_bytes`: encoded manifest
/// - `chunks`: ordered (cid_string, encrypted_bytes) pairs
/// - `recipient_secret`: X25519 private key (32 bytes)
pub fn process_download(
    manifest_bytes: &[u8],
    chunks: &[(String, Vec<u8>)],
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let manifest = crate::storage::manifest::decode_manifest(manifest_bytes)?;

    let ephemeral_pubkey: [u8; 32] = hex::decode(&manifest.ephemeral_pubkey)
        .map_err(|e| format!("invalid ephemeral pubkey hex: {}", e))?
        .try_into()
        .map_err(|_| "ephemeral pubkey must be 32 bytes".to_string())?;

    let symmetric_key = encrypt::unseal_file_key(recipient_secret, &ephemeral_pubkey);

    if chunks.len() != manifest.chunk_cids.len() {
        return Err(format!(
            "chunk count mismatch: manifest has {}, got {}",
            manifest.chunk_cids.len(),
            chunks.len()
        ));
    }

    let mut result = Vec::with_capacity(manifest.file_size as usize);

    for (i, (cid_str, encrypted)) in chunks.iter().enumerate() {
        // Verify CID matches manifest
        if *cid_str != manifest.chunk_cids[i] {
            return Err(format!(
                "CID mismatch at chunk {}: expected {}, got {}",
                i, manifest.chunk_cids[i], cid_str
            ));
        }

        // Verify CID matches actual data
        let computed_cid = cid_util::compute_cid(encrypted);
        let computed_cid_str = cid_util::cid_to_string(&computed_cid);
        if computed_cid_str != *cid_str {
            return Err(format!(
                "CID verification failed at chunk {}: content doesn't match CID",
                i
            ));
        }

        let decrypted = encrypt::decrypt_chunk(&symmetric_key, i as u64, encrypted)?;
        result.extend_from_slice(&decrypted);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_recipient() -> ([u8; 32], [u8; 32]) {
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (secret_bytes, *public.as_bytes())
    }

    #[test]
    fn full_roundtrip_small_file() {
        let (secret, pubkey) = make_recipient();
        let data = b"hello secure storage!";
        let bundle = prepare_upload(data, &pubkey, chunker::DEFAULT_CHUNK_SIZE, "text/plain");

        assert_eq!(bundle.chunks.len(), 1);
        assert!(!bundle.root_cid_string.is_empty());

        let recovered = process_download(&bundle.manifest_bytes, &bundle.chunks, &secret).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn full_roundtrip_multi_chunk() {
        let (secret, pubkey) = make_recipient();
        // Use small chunk size for test: 10 bytes
        let data = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bundle = prepare_upload(data, &pubkey, 10, "text/plain");

        assert_eq!(bundle.chunks.len(), 4); // 36 bytes / 10 = 4 chunks
        let recovered = process_download(&bundle.manifest_bytes, &bundle.chunks, &secret).unwrap();
        assert_eq!(recovered, data.as_slice());
    }

    #[test]
    fn tampered_chunk_detected() {
        let (secret, pubkey) = make_recipient();
        let data = b"tamper detection test data here";
        let mut bundle = prepare_upload(data, &pubkey, 10, "");

        // Tamper with the first chunk's data
        if let Some((_cid, ref mut encrypted)) = bundle.chunks.first_mut() {
            if encrypted.len() > 13 {
                encrypted[13] ^= 0xFF;
            }
        }

        let result = process_download(&bundle.manifest_bytes, &bundle.chunks, &secret);
        assert!(result.is_err(), "tampered chunk should be detected");
    }

    #[test]
    fn wrong_recipient_fails() {
        let (_secret, pubkey) = make_recipient();
        let (wrong_secret, _) = make_recipient();
        let data = b"wrong recipient test";
        let bundle = prepare_upload(data, &pubkey, chunker::DEFAULT_CHUNK_SIZE, "");

        let result = process_download(&bundle.manifest_bytes, &bundle.chunks, &wrong_secret);
        assert!(result.is_err(), "wrong recipient key should fail");
    }

    #[test]
    fn content_hash_is_32_bytes() {
        let (_, pubkey) = make_recipient();
        let bundle = prepare_upload(b"hash test", &pubkey, chunker::DEFAULT_CHUNK_SIZE, "");
        assert_eq!(bundle.content_hash.len(), 32);
        assert!(bundle.content_hash.iter().any(|&b| b != 0), "hash should not be all zeros");
    }
}
