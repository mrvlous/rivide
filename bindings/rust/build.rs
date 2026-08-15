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

//! Cargo build script for the `rivide` Rust crate.
//!
//! Automatically discovers and compiles the underlying C99 Rivide cryptographic
//! engine into a static archive (`librivide_c.a`) using the `cc` build dependency.

use std::path::{Path, PathBuf};

fn main() {
    let root = if Path::new("../../src/core/rivide_init.c").exists() {
        PathBuf::from("../..")
    } else if Path::new("c_src/src/core/rivide_init.c").exists() {
        PathBuf::from("c_src")
    } else if Path::new("deps/src/core/rivide_init.c").exists() {
        PathBuf::from("deps")
    } else {
        PathBuf::from(".")
    };

    let include_dir = root.join("include");
    let src_dir = root.join("src");

    let mut build = cc::Build::new();

    build
        .flag_if_supported("-std=c99")
        .flag_if_supported("-O3")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .include(&include_dir)
        .include(&src_dir);

    // Target OS specific configurations
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        build.define("_DARWIN_C_SOURCE", None);
    } else if target_os == "windows" {
        build.define("_CRT_SECURE_NO_WARNINGS", None);
    }

    let c_sources = [
        "core/rivide_init.c",
        "core/rivide_types.c",
        "utils/mem.c",
        "utils/random.c",
        "crypto/aes_core.c",
        "crypto/aes_gcm.c",
        "crypto/ghash.c",
        "crypto/keccak.c",
        "crypto/sha3.c",
        "pqc/ntt_simd.c",
        "pqc/ml_kem/kem_cbd.c",
        "pqc/ml_kem/kem_compress.c",
        "pqc/ml_kem/kem_encode.c",
        "pqc/ml_kem/kem_ntt.c",
        "pqc/ml_kem/kem_poly.c",
        "pqc/ml_kem/kem_reduce.c",
        "pqc/ml_kem/kem_sampling.c",
        "pqc/ml_kem/ml_kem.c",
        "pqc/ml_dsa/dsa_ntt.c",
        "pqc/ml_dsa/dsa_packing.c",
        "pqc/ml_dsa/dsa_poly.c",
        "pqc/ml_dsa/dsa_reduce.c",
        "pqc/ml_dsa/dsa_rounding.c",
        "pqc/ml_dsa/dsa_sampling.c",
        "pqc/ml_dsa/ml_dsa.c",
    ];

    for src_rel in &c_sources {
        let file_path = src_dir.join(src_rel);
        build.file(&file_path);
    }

    build.compile("rivide_c");

    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", src_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
}
