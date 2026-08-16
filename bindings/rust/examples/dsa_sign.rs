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

//! Demonstration example of ML-DSA-65 digital signatures in Rust.

use rivide::dsa::MlDsa65;

fn main() {
    println!("Rivide Rust: ML-DSA-65 Digital Signature Demonstration");

    // 1. Generate signing keypair
    println!("\n[Signer] Generating ML-DSA-65 signature keypair...");
    let signer = MlDsa65::keypair().expect("Failed to generate signer keypair");
    println!(
        "  Public Key : {} bytes",
        signer.public_key.as_bytes().len()
    );
    println!(
        "  Secret Key : {} bytes",
        signer.secret_key.as_bytes().len()
    );

    // 2. Sign arbitrary message payload
    let message = b"Post-quantum signed contract payload: Transfer $100,000 to Bob.";
    println!(
        "\n[Signer] Signing message: \"{}\"...",
        std::str::from_utf8(message).unwrap()
    );
    let signature = MlDsa65::sign(message, &signer.secret_key).expect("Failed to sign message");
    println!("  Signature  : {} bytes", signature.as_bytes().len());

    // 3. [Verifier] Verify signature authenticity
    println!("\n[Verifier] Verifying signature against public key...");
    let is_valid = MlDsa65::verify(&signature, message, &signer.public_key);
    if is_valid {
        println!("[SUCCESS] Signature is VALID and AUTHENTIC!");
    } else {
        panic!("FATAL: Signature verification failed!");
    }

    // 4. [Verifier] Test tamper rejection
    let tampered_msg = b"Post-quantum signed contract payload: Transfer $1,000,000 to Bob.";
    println!(
        "\n[Verifier] Testing tampered message: \"{}\"...",
        std::str::from_utf8(tampered_msg).unwrap()
    );
    let is_tampered_valid = MlDsa65::verify(&signature, tampered_msg, &signer.public_key);
    if !is_tampered_valid {
        println!("[SUCCESS] Tampered message correctly REJECTED!");
    } else {
        panic!("FATAL: Tampered message was incorrectly accepted!");
    }
}
