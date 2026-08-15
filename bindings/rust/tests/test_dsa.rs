// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

use rivide::dsa::{MlDsa65, MlDsa87};

#[test]
fn test_ml_dsa_65_roundtrip() {
    let signer = MlDsa65::keypair().expect("ML-DSA-65 KeyGen failed");
    assert_eq!(signer.public_key.as_bytes().len(), 1952);
    assert_eq!(signer.secret_key.as_bytes().len(), 4032);

    let message = b"Post-Quantum Rust Digital Signature Test Payload";
    let signature = MlDsa65::sign(message, &signer.secret_key).expect("Signing failed");
    assert_eq!(signature.as_bytes().len(), 3309);

    let is_valid = MlDsa65::verify(&signature, message, &signer.public_key);
    assert!(is_valid);
}

#[test]
fn test_ml_dsa_65_tamper_rejection() {
    let signer = MlDsa65::keypair().expect("KeyGen failed");
    let message = b"Valid Transaction Amount: $100";
    let signature = MlDsa65::sign(message, &signer.secret_key).expect("Signing failed");

    // Tamper with message
    let tampered_msg = b"Tampered Transaction Amount: $10,000";
    let is_valid = MlDsa65::verify(&signature, tampered_msg, &signer.public_key);
    assert!(!is_valid);

    // Tamper with signature
    let mut tampered_sig = *signature.as_bytes();
    tampered_sig[100] ^= 0xFF;
    let corrupted_sig = rivide::dsa::MlDsa65Signature::from_bytes(tampered_sig);
    let is_valid2 = MlDsa65::verify(&corrupted_sig, message, &signer.public_key);
    assert!(!is_valid2);
}

#[test]
fn test_ml_dsa_87_roundtrip() {
    let signer = MlDsa87::keypair().expect("ML-DSA-87 KeyGen failed");
    assert_eq!(signer.public_key.as_bytes().len(), 2592);
    assert_eq!(signer.secret_key.as_bytes().len(), 4896);

    let message = b"Security Category 5 Document";
    let signature = MlDsa87::sign(message, &signer.secret_key).expect("Signing failed");
    assert_eq!(signature.as_bytes().len(), 4627);

    let is_valid = MlDsa87::verify(&signature, message, &signer.public_key);
    assert!(is_valid);
}
