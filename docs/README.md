<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide Documentation Portal

Welcome to the **Rivide Post-Quantum Cryptography (PQC) Library** comprehensive technical documentation portal.

Rivide is an industrial-grade, zero-allocation, constant-time C99 post-quantum cryptography library providing full implementations of the finalized NIST post-quantum standards (**NIST FIPS 203 ML-KEM** and **NIST FIPS 204 ML-DSA**) with native bindings for **Node.js / TypeScript**, **Rust**, and **Python**.

## Documentation Directory Index

### 1. [Getting Started](getting_started/overview.md)
- **[Overview](getting_started/overview.md)**: Architectural introduction, quantum threat timeline, and NIST standard alignment.
- **[C99 Quickstart](getting_started/quickstart_c.md)**: Compiling, header linking, and basic key exchange in C.
- **[Node.js / TypeScript Quickstart](getting_started/quickstart_node.md)**: Installing via `npm`, `pnpm`, or `yarn` and using the Node-API native bindings.
- **[Rust Quickstart](getting_started/quickstart_rust.md)**: Adding `rivide` via `cargo add` and using idiomatic RAII wrappers.
- **[Python Quickstart](getting_started/quickstart_python.md)**: Loading `librivide.so` via `ctypes` FFI.

### 2. [Mathematical Algorithms & Standards](algorithms/ml_kem_fips203.md)
- **[NIST FIPS 203 ML-KEM](algorithms/ml_kem_fips203.md)**: Mathematical ring quotient $\mathcal{R}_q$, CBD noise sampling, Fujisaki-Okamoto transform.
- **[NIST FIPS 204 ML-DSA](algorithms/ml_dsa_fips204.md)**: Fiat-Shamir with Aborts, power-of-2 rounding, rejection sampling bounds.
- **[NTT & Modular Arithmetic](algorithms/ntt_and_reductions.md)**: Cooley-Tukey butterfly arithmetic, Montgomery & Barrett reduction proofs.
- **[SHA-3 & Keccak Sponge](algorithms/sha3_and_keccak.md)**: Keccak-f[1600] permutation, SHA3-256/512, and SHAKE-128/256 XOF.
- **[AES-GCM AEAD](algorithms/aes_gcm_aead.md)**: Galois/Counter Mode authenticated encryption and GHASH field multiplication.

### 3. [System Architecture](architecture/overview.md)
- **[Subsystem Overview](architecture/overview.md)**: Software architecture, component boundaries, and module responsibilities.
- **[Zero-Allocation Memory Model](architecture/memory_model.md)**: 0 Malloc principle, stack isolation, and volatile memory cleansing.
- **[Hardware Acceleration](architecture/hardware_acceleration.md)**: 256-bit AVX2 and 128-bit ARM NEON SIMD vector optimization and CPU dispatch.
- **[Node.js Bindings Architecture](architecture/node_bindings.md)**: Native Node-API C addon architecture and V8 garbage collector interaction.
- **[Rust Bindings Architecture](architecture/rust_bindings.md)**: Raw FFI layers, safe abstractions, RAII zeroization, and crates.io bundling.

### 4. [Security & Side-Channel Hardening](security/threat_model.md)
- **[Threat Model & Security Goals](security/threat_model.md)**: IND-CCA2 and EUF-CMA formal adversary models.
- **[Constant-Time Engineering](security/constant_time.md)**: Elimination of secret-dependent branches, cache-timing mitigation, and constant-time comparators.
- **[Memory Safety Guarantees](security/memory_safety.md)**: Dead-store elimination prevention, volatile memory barriers, and spatial safety.
- **[Vulnerability Reporting](security/vulnerability_reporting.md)**: Responsible disclosure contact and PGP communication procedures.

### 5. Cross-Language API References
- **C99 API Reference**:
  - [Core Engine API](api/c/core.md)
  - [ML-KEM Key Encapsulation API](api/c/ml_kem.md)
  - [ML-DSA Digital Signatures API](api/c/ml_dsa.md)
  - [Symmetric & Memory Utilities API](api/c/crypto_utils.md)
  - [Low-Level NTT & SIMD API](api/c/ntt_simd.md)
- **Node.js API Reference**:
  - [Node.js TypeScript API](api/node/api.md)
- **Rust API Reference**:
  - [Rust Crate API](api/rust/api.md)

### 6. [Performance & Benchmarking](benchmarks/methodology.md)
- **[Benchmarking Methodology](benchmarks/methodology.md)**: Nanosecond monotonic timing, warmup protocol, and statistical reporting.
- **[C Native Benchmarks](benchmarks/c_benchmarks.md)**: Running and configuring `make bench`.
- **[Node.js Runtime Benchmarks](benchmarks/node_benchmarks.md)**: Running and configuring `make node-bench`.
- **[Rust Crate Benchmarks](benchmarks/rust_benchmarks.md)**: Running and configuring `make rust-bench`.

### 7. [Quality Assurance & Testing](testing/unit_tests.md)
- **[Automated Unit Tests](testing/unit_tests.md)**: Unit test suite execution via `make test`.
- **[NIST Known Answer Tests (KAT)](testing/nist_kat.md)**: Byte-exact CAVP test vector validation via `make kat`.
- **[LLVM libFuzzer Fuzzing](testing/fuzzing.md)**: Continuous coverage-guided fuzzing targets via `make fuzz`.

### 8. [Real-World Deployment Use Cases](use_cases/network_tls.md)
- **[TLS 1.3 Quantum-Safe Handshake](use_cases/network_tls.md)**: Hybrid post-quantum key exchange for network protocols.
- **[Cloud Storage Vault](use_cases/cloud_storage.md)**: End-to-end encrypted storage vaults using ML-KEM and AES-256-GCM.
- **[Embedded & Edge IoT](use_cases/embedded_iot.md)**: Microcontroller deployments with zero heap memory overhead.
- **[Post-Quantum JWT Tokens](use_cases/web_jwt.md)**: Quantum-resistant authentication tokens using ML-DSA digital signatures.
- **[Detached Document Signing](use_cases/document_signing.md)**: Contract and PDF signing workflows with detached signatures.

### 9. [Contributing Guidelines](contributing/setup.md)
- **[Development Setup](contributing/setup.md)**: Toolchain requirements (GCC, Clang, CMake, Node.js, Rust).
- **[Build System Guide](contributing/build.md)**: Detailed Makefile targets and CMake build variables.
- **[Coding Style & Standards](contributing/style.md)**: ISO C99 rules, zero-malloc constraints, and Doxygen conventions.
