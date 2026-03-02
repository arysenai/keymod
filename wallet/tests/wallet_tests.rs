use arysen_wallet::{ed25519, secp256k1, storage, types::KeyPair};

#[test]
fn ed25519_keypair_structure() {
    let kp = ed25519::generate_keypair();
    assert_eq!(kp.pub_key.len(), 32, "Ed25519 pubkey must be 32 bytes");
    assert!(!kp.key_id.is_empty(), "key_id must not be empty");
}

#[test]
fn secp256k1_keypair_structure() {
    let kp = secp256k1::generate_keypair();
    assert_eq!(kp.pub_key.len(), 33, "secp256k1 compressed pubkey must be 33 bytes");
    assert!(!kp.key_id.is_empty(), "key_id must not be empty");
}

#[test]
fn ed25519_sign_returns_64_byte_signature() {
    let sig = ed25519::sign(b"test message", "key-1");
    assert_eq!(sig.0.len(), 64);
}

#[test]
fn secp256k1_sign_returns_65_byte_signature() {
    let sig = secp256k1::sign(b"test message", "key-1");
    assert_eq!(sig.0.len(), 65);
}

#[test]
fn ed25519_real_crypto_roundtrip() {
    let (pub_key, priv_key) = ed25519::generate_keypair_raw();
    let msg = b"integration test message";
    let sig = ed25519::sign_raw(msg, &priv_key);
    assert_eq!(sig.0.len(), 64);
    assert!(ed25519::verify(msg, &sig.0, &pub_key));
    // Wrong message should fail
    assert!(!ed25519::verify(b"wrong", &sig.0, &pub_key));
}

#[test]
fn secp256k1_real_crypto_roundtrip() {
    let (pub_key, priv_key) = secp256k1::generate_keypair_raw();
    let msg = b"integration test message";
    let sig = secp256k1::sign_raw(msg, &priv_key);
    assert_eq!(sig.0.len(), 65);
    assert!(secp256k1::verify(msg, &sig.0, &pub_key));
    // Wrong message should fail
    assert!(!secp256k1::verify(b"wrong", &sig.0, &pub_key));
}

#[test]
fn invalid_key_rejects_verification() {
    // Random garbage as pubkey/signature should not verify
    assert!(!secp256k1::verify(b"msg", &[0xffu8; 65], &[0x02; 33]));
}

#[test]
fn aes_gcm_roundtrip_integration() {
    let plaintext = b"integration test secret";
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).unwrap();
    let encrypted = storage::encrypt_key(plaintext, &key).unwrap();
    let decrypted = storage::decrypt_key(&encrypted, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn keypair_serializes_to_json() {
    let kp = KeyPair {
        pub_key: vec![1, 2, 3],
        key_id: "test".to_string(),
    };
    let json = serde_json::to_string(&kp).unwrap();
    assert!(json.contains("\"key_id\":\"test\""));
}
