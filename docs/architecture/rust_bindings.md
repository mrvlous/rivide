<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rust Native Crate Subsystem Architecture

This document describes the design, directory structure, memory safety guarantees, and execution model of the official **Rivide** Rust native bindings crate (`bindings/rust/`).

## Subsystem Organization

```
bindings/rust/
├── Cargo.toml           # Standard Rust crate manifest for 'rivide' v1.1.3
├── build.rs             # C99 source compiler using cc crate
├── README.md            # Dedicated crates.io documentation & quick start
├── CHANGELOG.md         # Dedicated release changelog for Rust crate
├── LICENSE              # Dedicated MIT license file
├── docs/
│   ├── api.md           # Standalone Rust crate API reference
│   └── benchmarks.md    # Rust performance benchmarking guide
├── benches/
│   └── bench_pqc.rs     # Performance benchmark suite
├── src/
│   ├── lib.rs           # Crate root re-exports, documentation & doctests
│   ├── sys.rs           # Raw extern "C" FFI declarations matching C headers
│   ├── error.rs         # Strongly typed RivideError enum & Result conversions
│   ├── kem.rs           # Safe ML-KEM-768 & ML-KEM-1024 types and methods
│   ├── dsa.rs           # Safe ML-DSA-65 & ML-DSA-87 types and methods
│   ├── crypto.rs        # Safe SHA-3, SHAKE XOF & AES-GCM AEAD wrappers
│   └── utils.rs         # Cleanse, randombytes, ct_memcmp & CPU feature queries
├── tests/
│   ├── test_kem.rs      # Integration tests for ML-KEM routines & rejections
│   ├── test_dsa.rs      # Integration tests for ML-DSA signature routines
│   └── test_crypto.rs   # Integration tests for symmetric crypto & utilities
└── examples/
    ├── kem_exchange.rs   # ML-KEM-768 key encapsulation demonstration
    ├── dsa_sign.rs       # ML-DSA-65 digital signature demonstration
    ├── hybrid_channel.rs # Hybrid PQC + AES-256-GCM authenticated channel
    └── bench.rs          # Executable benchmark runner example
```

## Technical Architecture

1. **Zero-Setup C99 Compilation**:
   - `build.rs` compiles the core Rivide C99 source files directly into the resulting Rust crate static archive via the `cc` build dependency.
   - Requires zero external pre-installed C shared libraries or package configurations.
2. **Zero Heap Allocation Architecture**:
   - Cryptographic keys, ciphertexts, and signatures use fixed-size stack arrays (`[u8; N]`) to avoid dynamic memory allocator overhead in performance-critical cryptographic paths.
3. **RAII Memory Safety & Automated Cleansing**:
   - Secret key structures (`MlKem768SecretKey`, `MlKem1024SecretKey`, `MlDsa65SecretKey`, `MlDsa87SecretKey`) implement the `Drop` trait to automatically call `rivide_cleanse` upon exiting scope.
   - Prevents sensitive private key material from lingering in heap or stack memory.
4. **Strong Typing & Error Model**:
   - Exposes `Result<T, RivideError>` for fallible operations with descriptive error variants.

## Build and Test Automation

```bash
# Compile and build Rust crate
cargo build --release

# Run automated integration tests and doctests
cargo test

# Run high-precision performance benchmarks
cargo bench

# Run demonstration examples
cargo run --example kem_exchange
cargo run --example dsa_sign
cargo run --example hybrid_channel
```
