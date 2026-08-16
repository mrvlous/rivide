<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **`rivide`** Rust crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-08-16

### Fixed
- **Thread-Safe Atomic RNG Callback Registration**:
  - Implemented atomic synchronization for custom entropy callbacks using release-acquire memory ordering, guaranteeing zero data races when invoked across multi-threaded Rayon workers or Tokio task pools.

### Added
- **Constant-Time Statistical Timing Verification**:
  - Formally verified constant-time decapsulation and memory comparisons (`ct_memcmp`) using the Dudect Welch's t-test methodology ($|t| < 4.5$).
  - Added dedicated Makefile targets `make timing` and `make rust-publish`.

### Security
- **Concurrency & Timing Attack Hardening**:
  - Validated statistical timing leakage boundaries across safe Rust wrapper abstractions.
  - Documented formal concurrency guarantees and thread-safety invariants.

### Documentation
- **API & Benchmark Guides**:
  - Updated Rust crate documentation, doctests, and examples to version `1.1.1`.
  - Added publishing instructions for crates.io and sandbox package verification guides.

## [1.1.0] - 2026-08-15

### Added
- **Initial Release of Official Rust Native Bindings (`rivide`)**:
  - Direct, zero-dependency C99 compilation via `build.rs` and `cc` crate.
- **NIST Post-Quantum Cryptography Modules**:
  - `MlKem768`: ML-KEM-768 keypair generation (`keypair`), encapsulation (`encapsulate`), and constant-time decapsulation (`decapsulate`).
  - `MlKem1024`: ML-KEM-1024 keypair generation (`keypair`), encapsulation (`encapsulate`), and constant-time decapsulation (`decapsulate`).
  - `MlDsa65`: ML-DSA-65 keypair generation (`keypair`), signing (`sign`), and strict signature verification (`verify`).
  - `MlDsa87`: ML-DSA-87 keypair generation (`keypair`), signing (`sign`), and strict signature verification (`verify`).
- **Symmetric Cryptography & Utility Modules**:
  - `Sha3`: SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 extendable-output hashing.
  - `AesGcm`: AES-128-GCM and AES-256-GCM authenticated encryption and decryption.
  - `utils`: Secure memory zeroization (`cleanse`), OS CSPRNG entropy generation (`randombytes`), constant-time memory comparison (`ct_memcmp`), and runtime hardware CPU feature detection (`get_cpu_features`).
- **Developer Ergonomics & Memory Safety**:
  - Automated RAII memory cleansing (`Drop` trait implementation invoking `rivide_cleanse` for all secret keys).
  - Fixed-size stack-allocated arrays (`[u8; N]`) for zero heap allocation overhead.
  - Dedicated unit and integration tests (`tests/`), standalone executable examples (`examples/`), and high-precision performance benchmark harness (`benches/bench_pqc.rs`).
