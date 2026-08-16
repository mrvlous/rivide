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

//! Rust performance benchmark suite for Rivide Post-Quantum Cryptography.

use rivide::crypto::{AesGcm, Sha3};
use rivide::dsa::{MlDsa65, MlDsa87};
use rivide::kem::{MlKem1024, MlKem768};
use rivide::utils::{get_cpu_features, version};
use std::time::Instant;

fn benchmark<F: FnMut()>(name: &str, mut f: F, iterations: usize) {
    // Warmup
    for _ in 0..50 {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let duration = start.elapsed();
    let duration_sec = duration.as_secs_f64();
    let ops_per_sec = iterations as f64 / duration_sec;
    let us_per_op = (duration_sec / iterations as f64) * 1_000_000.0;

    println!(
        "  {:<28} : {:>9.2} ops/sec ({:>7.2} us/op)",
        name, ops_per_sec, us_per_op
    );
}

fn main() {
    println!(
        "Rivide Rust Post-Quantum Cryptography Benchmark Suite v{}\n",
        version()
    );
    let cpu = get_cpu_features();
    println!(
        "Hardware Acceleration : AVX2: {}, AES-NI: {}, NEON: {}, ARM-CE: {}\n",
        if cpu.has_avx2 { "YES" } else { "NO" },
        if cpu.has_aesni { "YES" } else { "NO" },
        if cpu.has_neon { "YES" } else { "NO" },
        if cpu.has_arm_ce { "YES" } else { "NO" },
    );

    let iters = 1000;

    println!("NIST FIPS 203 ML-KEM Benchmarks:");
    let kem768_kp = MlKem768::keypair().unwrap();
    let kem768_enc = MlKem768::encapsulate(&kem768_kp.public_key).unwrap();
    benchmark(
        "ML-KEM-768 KeyGen",
        || {
            let _ = MlKem768::keypair();
        },
        iters,
    );
    benchmark(
        "ML-KEM-768 Encaps",
        || {
            let _ = MlKem768::encapsulate(&kem768_kp.public_key);
        },
        iters,
    );
    benchmark(
        "ML-KEM-768 Decaps",
        || {
            let _ = MlKem768::decapsulate(&kem768_enc.ciphertext, &kem768_kp.secret_key);
        },
        iters,
    );

    println!();
    let kem1024_kp = MlKem1024::keypair().unwrap();
    let kem1024_enc = MlKem1024::encapsulate(&kem1024_kp.public_key).unwrap();
    benchmark(
        "ML-KEM-1024 KeyGen",
        || {
            let _ = MlKem1024::keypair();
        },
        iters,
    );
    benchmark(
        "ML-KEM-1024 Encaps",
        || {
            let _ = MlKem1024::encapsulate(&kem1024_kp.public_key);
        },
        iters,
    );
    benchmark(
        "ML-KEM-1024 Decaps",
        || {
            let _ = MlKem1024::decapsulate(&kem1024_enc.ciphertext, &kem1024_kp.secret_key);
        },
        iters,
    );

    println!("\nNIST FIPS 204 ML-DSA Benchmarks:");
    let dsa65_kp = MlDsa65::keypair().unwrap();
    let sample_msg = b"Quantum-safe payload for Rust digital signature benchmarking.";
    let dsa65_sig = MlDsa65::sign(sample_msg, &dsa65_kp.secret_key).unwrap();
    benchmark(
        "ML-DSA-65 KeyGen",
        || {
            let _ = MlDsa65::keypair();
        },
        iters,
    );
    benchmark(
        "ML-DSA-65 Sign",
        || {
            let _ = MlDsa65::sign(sample_msg, &dsa65_kp.secret_key);
        },
        iters,
    );
    benchmark(
        "ML-DSA-65 Verify",
        || {
            let _ = MlDsa65::verify(&dsa65_sig, sample_msg, &dsa65_kp.public_key);
        },
        iters,
    );

    println!();
    let dsa87_kp = MlDsa87::keypair().unwrap();
    let dsa87_sig = MlDsa87::sign(sample_msg, &dsa87_kp.secret_key).unwrap();
    benchmark(
        "ML-DSA-87 KeyGen",
        || {
            let _ = MlDsa87::keypair();
        },
        iters,
    );
    benchmark(
        "ML-DSA-87 Sign",
        || {
            let _ = MlDsa87::sign(sample_msg, &dsa87_kp.secret_key);
        },
        iters,
    );
    benchmark(
        "ML-DSA-87 Verify",
        || {
            let _ = MlDsa87::verify(&dsa87_sig, sample_msg, &dsa87_kp.public_key);
        },
        iters,
    );

    println!("\nSymmetric Primitives Benchmarks:");
    let payload_4kb = vec![0x42u8; 4096];
    let key32 = [0x01u8; 32];
    let iv12 = [0x02u8; 12];
    let enc_res = AesGcm::encrypt_256(&key32, &iv12, &payload_4kb, None).unwrap();

    benchmark(
        "SHA3-256 (4 KB)",
        || {
            let _ = Sha3::sha3_256(&payload_4kb);
        },
        iters,
    );
    benchmark(
        "SHAKE-256 (4 KB -> 32B)",
        || {
            let _ = Sha3::shake256(&payload_4kb, 32);
        },
        iters,
    );
    benchmark(
        "AES-256-GCM Encrypt (4 KB)",
        || {
            let _ = AesGcm::encrypt_256(&key32, &iv12, &payload_4kb, None);
        },
        iters,
    );
    benchmark(
        "AES-256-GCM Decrypt (4 KB)",
        || {
            let _ = AesGcm::decrypt_256(&key32, &iv12, &enc_res.ciphertext, &enc_res.tag, None);
        },
        iters,
    );

    println!("\n[SUCCESS] Rust Benchmark Suite Execution Complete.");
}
