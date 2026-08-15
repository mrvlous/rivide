// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

//! Integration tests for ML-KEM-768 and ML-KEM-1024.

use rivide::kem::{MlKem1024, MlKem768};
use rivide::utils::ct_memcmp;

#[test]
fn test_ml_kem_768_roundtrip() {
    let alice = MlKem768::keypair().expect("ML-KEM-768 KeyGen failed");
    assert_eq!(alice.public_key.as_bytes().len(), 1184);
    assert_eq!(alice.secret_key.as_bytes().len(), 2400);

    let bob = MlKem768::encapsulate(&alice.public_key).expect("ML-KEM-768 Encaps failed");
    assert_eq!(bob.ciphertext.len(), 1088);
    assert_eq!(bob.shared_secret.len(), 32);

    let alice_ss =
        MlKem768::decapsulate(&bob.ciphertext, &alice.secret_key).expect("ML-KEM-768 Decaps failed");

    assert_eq!(alice_ss, bob.shared_secret);
    assert_eq!(ct_memcmp(&alice_ss, &bob.shared_secret), 0);
}

#[test]
fn test_ml_kem_768_implicit_rejection() {
    let alice = MlKem768::keypair().expect("KeyGen failed");
    let bob = MlKem768::encapsulate(&alice.public_key).expect("Encaps failed");

    let mut tampered_ct = bob.ciphertext;
    tampered_ct[0] ^= 0x01; // Corrupt ciphertext byte

    let alice_ss =
        MlKem768::decapsulate(&tampered_ct, &alice.secret_key).expect("Decaps should succeed via implicit rejection");

    // Must NOT match bob's shared secret
    assert_ne!(alice_ss, bob.shared_secret);
}

#[test]
fn test_ml_kem_1024_roundtrip() {
    let alice = MlKem1024::keypair().expect("ML-KEM-1024 KeyGen failed");
    assert_eq!(alice.public_key.as_bytes().len(), 1568);
    assert_eq!(alice.secret_key.as_bytes().len(), 3168);

    let bob = MlKem1024::encapsulate(&alice.public_key).expect("ML-KEM-1024 Encaps failed");
    assert_eq!(bob.ciphertext.len(), 1568);
    assert_eq!(bob.shared_secret.len(), 32);

    let alice_ss =
        MlKem1024::decapsulate(&bob.ciphertext, &alice.secret_key).expect("ML-KEM-1024 Decaps failed");

    assert_eq!(alice_ss, bob.shared_secret);
    assert_eq!(ct_memcmp(&alice_ss, &bob.shared_secret), 0);
}
