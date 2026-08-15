// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

use rivide::crypto::{AesGcm, Sha3};
use rivide::utils::{cleanse, ct_memcmp, get_cpu_features, randombytes, version};

#[test]
fn test_sha3_known_vector() {
    let empty_sha3_256 = Sha3::sha3_256(b"");
    let hex_digest = hex_encode(&empty_sha3_256);
    assert_eq!(
        hex_digest,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );

    let shake = Sha3::shake256(b"", 32);
    assert_eq!(shake.len(), 32);
}

#[test]
fn test_aes_256_gcm_roundtrip() {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    let plaintext = b"Rust Confidential Message for Post-Quantum Channel";
    let aad = b"Header:Rust-AESGCM";

    let encrypted = AesGcm::encrypt_256(&key, &iv, plaintext, Some(aad)).expect("Encryption failed");
    assert_eq!(encrypted.ciphertext.len(), plaintext.len());
    assert_eq!(encrypted.tag.len(), 16);

    let decrypted = AesGcm::decrypt_256(&key, &iv, &encrypted.ciphertext, &encrypted.tag, Some(aad))
        .expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_utils_functions() {
    let mut secret = [0x55u8; 64];
    cleanse(&mut secret);
    assert_eq!(secret, [0u8; 64]);

    let random_bytes = randombytes(32).expect("Entropy generation failed");
    assert_eq!(random_bytes.len(), 32);

    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];
    assert_eq!(ct_memcmp(&a, &b), 0);
    assert_ne!(ct_memcmp(&a, &c), 0);

    let cpu = get_cpu_features();
    println!("Detected CPU Features: {:?}", cpu);

    let ver = version();
    assert_eq!(ver, "1.1.0");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
