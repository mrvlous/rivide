<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **Rivide** Post-Quantum Cryptography library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-08-14

### Fixed
- **Strict Signature Length Validation in ML-DSA (Security Audit P0 Remediation)**:
  - Enforced strict buffer length validation in `rivide_ml_dsa_65_verify` and `rivide_ml_dsa_87_verify` against expected encoded signature sizes (`RIVIDE_ML_DSA_65_SIG_BYTES = 3309`, `RIVIDE_ML_DSA_87_SIG_BYTES = 4627`).
  - Corrected `ml_dsa_verify_internal` to strictly reject both truncated (`siglen < expected`) and oversized (`siglen > expected`) signatures with `RIVIDE_ERR_VERIFICATION_FAILED` before deserialization, preventing potential out-of-bounds reads and undefined behavior.
- **Python CTypes FFI Binding (`examples/python/rivide_pqc_binding.py`)**:
  - Corrected function symbol from `rivide_ml_kem_768_keypair` to `rivide_ml_kem_768_keygen` to align with the public C library API.

### Added
- **Security Regression & Boundary Fuzzing Test Suite**:
  - Added `test_ml_dsa_65_siglen_validation` and `test_ml_dsa_87_siglen_validation` testing signature length boundaries (`siglen = 0, 1, 2, expected-1, expected, expected+1, expected+32`).
  - Added `test_ml_dsa_boundary_fuzz` verifying robust rejection on corrupted challenge seeds ($c$), corrupted $z$ polynomials, corrupted hint vectors ($h$), corrupted public keys, NULL pointers, and empty messages (`msglen = 0`).
- **Mathematical NTT/INTT Invertibility & Modular Reduction Tests**:
  - Added `test_ml_kem_ntt_invertibility` verifying roundtrip invertibility of $\text{INTT}(\text{NTT}(x))$ modulo $q = 3329$.
  - Added `test_ml_dsa_ntt_invertibility` verifying roundtrip invertibility of $\text{INTT}(\text{NTT}(x))$ modulo $q = 8380417$.
  - Added `test_modular_reductions` verifying Barrett reduction and conditional modular addition ($q$).
- **ASan & UBSan Sanitizer Conformance Verification**:
  - Verified full test suite execution under AddressSanitizer (`-fsanitize=address`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`) with zero warnings, zero memory leaks, and zero undefined behaviors.

### Changed
- **API Documentation (`docs/api/ml_dsa.md`)**:
  - Documented explicit `siglen` buffer requirements and `RIVIDE_ERR_VERIFICATION_FAILED` error return code for ML-DSA verification functions.

---

## [1.0.0] - 2026-08-13

### Added
- **Initial Production-Ready Release (`v1.0.0`)**:
  - Official production release of the Rivide Post-Quantum Cryptography C99 library.
- **NIST Post-Quantum Cryptography Subsystems**:
  - Implemented **NIST FIPS 203** Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
  - Implemented **NIST FIPS 204** Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
  - Implemented Fujisaki-Okamoto (FO) transform with constant-time implicit rejection for ML-KEM decapsulation.
- **Hyper-Modular C99 Architecture**:
  - Modularized codebase into single-responsibility submodules (`src/core/`, `src/utils/`, `src/crypto/`, `src/pqc/ml_kem/`, `src/pqc/ml_dsa/`).
  - Separated public headers cleanly into `include/rivide/` hierarchy (`core/`, `crypto/`, `pqc/`).
  - Provided private internal headers under `include/rivide/internal/` for polynomial arithmetic, NTT transforms, and sampling routines.
- **Symmetric Cryptography Engine**:
  - Built-in 1600-bit Keccak-f[1600] 24-round permutation engine (NIST FIPS 202).
  - Implemented SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 extendable-output functions (XOF).
  - Implemented software table-free constant-time AES-128/256-GCM AEAD encryption and GHASH authentication (NIST SP 800-38D).
- **Hardware Acceleration & SIMD Vector Engine**:
  - Runtime and compile-time CPU feature detection for AES-NI, ARM Crypto Extensions, AVX2 SIMD, and ARM NEON SIMD (`rivide_get_cpu_features()`).
  - 8-way SIMD vectorization engine for AVX2 (256-bit `__m256i`) and ARM NEON (128-bit `int16x8_t`) polynomial coefficient vector math.
- **Constant-Time & Zero-Allocation Memory Guarantees**:
  - **Zero Dynamic Allocation (0% `malloc`)**: All data structures and buffers are caller-allocated on the stack or in static memory.
  - Constant-time memory comparison (`rivide_ct_memcmp`) and conditional selector (`rivide_ct_select`).
  - Volatile memory zeroization barrier (`rivide_cleanse`) preventing compiler dead-store elimination.
- **Granular Test Suite & PQC Benchmark Harness**:
  - Granular 14-test unit test suite executed via CTest (`make test`).
  - Performance benchmarking suite measuring operations-per-second and latency (`make bench`).
  - 8 standalone executable demonstration programs under `examples/` covering key exchange, digital signatures, hybrid AEAD, TLS 1.3 handshakes, secure vault storage, and Python CTypes FFI bindings.
- **Cross-Platform Tooling & Build System**:
  - Strict ISO C99 compliance (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
  - Master CMake build system (`CMakeLists.txt`) and master Makefile (`Makefile`).
  - IDE integration configuration files: `.clangd` (LSP), `.clang-format`, `.clang-tidy`, `.editorconfig`, `.gitattributes`, `.gitignore`.
