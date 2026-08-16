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

//! Demonstration example of hybrid ML-KEM-768 and AES-256-GCM secure channel in Rust.

use rivide::crypto::AesGcm;
use rivide::kem::MlKem768;
use rivide::utils::randombytes;

fn main() {
    println!("Rivide Rust: Hybrid PQC + AES-256-GCM Secure Channel");

    // 1. [Server] Provision ephemeral ML-KEM-768 keypair
    println!("\n[Server] Generating ephemeral ML-KEM-768 keypair...");
    let server = MlKem768::keypair().expect("Server KeyGen failed");

    // 2. [Client] Encapsulate 256-bit symmetric session key
    println!("\n[Client] Encapsulating symmetric session key under server's public key...");
    let kem = MlKem768::encapsulate(&server.public_key).expect("Client encapsulation failed");
    let session_key = kem.shared_secret; // 32-byte quantum-safe key

    // 3. [Client] Encrypt message payload using AES-256-GCM AEAD
    let payload = b"CONFIDENTIAL: Sovereign post-quantum financial wire instructions.";
    let iv_bytes = randombytes(12).expect("Entropy failed");
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    let aad = b"Protocol:TLS1.3-PQC-Hybrid";

    println!("\n[Client] Encrypting payload ({} bytes) with AES-256-GCM...", payload.len());
    let encrypted = AesGcm::encrypt_256(&session_key, &iv, payload, Some(aad))
        .expect("AES-GCM encryption failed");
    println!("  Ciphertext : {} bytes", encrypted.ciphertext.len());
    println!("  Auth Tag   : {:02x?}", &encrypted.tag);

    // 4. [Server] Decapsulate symmetric key and decrypt payload
    println!("\n[Server] Decapsulating symmetric key and decrypting payload...");
    let server_key =
        MlKem768::decapsulate(&kem.ciphertext, &server.secret_key).expect("Decapsulation failed");

    let decrypted = AesGcm::decrypt_256(
        &server_key,
        &iv,
        &encrypted.ciphertext,
        &encrypted.tag,
        Some(aad),
    )
    .expect("AES-GCM decryption failed");

    println!(
        "\n[Server] Decrypted Payload: \"{}\"",
        std::str::from_utf8(&decrypted).unwrap()
    );

    assert_eq!(&decrypted, payload);
    println!("\n[SUCCESS] End-to-end post-quantum authenticated tunnel verified!");
}
