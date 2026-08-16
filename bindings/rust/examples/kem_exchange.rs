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

//! Demonstration example of ML-KEM-768 quantum-safe key exchange in Rust.

use rivide::kem::MlKem768;
use rivide::utils::ct_memcmp;

fn main() {
    println!("Rivide Rust: ML-KEM-768 Key Exchange Demonstration");

    // 1. [Alice] Generate ML-KEM-768 keypair
    println!("\n[Alice] Generating ML-KEM-768 keypair...");
    let alice = MlKem768::keypair().expect("Failed to generate Alice's keypair");
    println!("  Public Key : {} bytes", alice.public_key.as_bytes().len());
    println!("  Secret Key : {} bytes", alice.secret_key.as_bytes().len());

    // 2. [Bob] Encapsulate shared secret under Alice's public key
    println!("\n[Bob] Encapsulating 32-byte shared secret using Alice's public key...");
    let bob = MlKem768::encapsulate(&alice.public_key).expect("Bob encapsulation failed");
    println!("  Ciphertext : {} bytes", bob.ciphertext.len());
    println!("  Shared Key : {:02x?}...", &bob.shared_secret[0..8]);

    // 3. [Alice] Decapsulate shared secret using her secret key
    println!("\n[Alice] Decapsulating shared secret from received ciphertext...");
    let alice_shared_secret = MlKem768::decapsulate(&bob.ciphertext, &alice.secret_key)
        .expect("Alice decapsulation failed");
    println!("  Decaps Key : {:02x?}...", &alice_shared_secret[0..8]);

    // 4. Verify shared secret match in constant time
    if ct_memcmp(&alice_shared_secret, &bob.shared_secret) == 0 {
        println!("\n[SUCCESS] Quantum-safe shared secret established perfectly!");
    } else {
        panic!("FATAL: Shared secret mismatch!");
    }
}
