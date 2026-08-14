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

## [1.1.0] - 2026-08-14

### Added
- **Dedicated NIST Known Answer Test (KAT) Subsystem**:
  - Implemented a standalone, modular KAT verification framework under [`tests/kat/`](tests/kat/) with reproducible byte-exact vector validation:
    - `test_kat_harness.h`: Standardized KAT comparison macros, hex string parser, and result accounting.
    - `test_kat_sha3.c`: Official NIST FIPS 202 CAVP test vectors for SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 across empty, short, and multi-block inputs.
    - `test_kat_ml_kem.c`: NIST FIPS 203 functional KAT vectors and deterministic constant-time implicit rejection consistency checks for ML-KEM-768 and ML-KEM-1024.
    - `test_kat_ml_dsa.c`: NIST FIPS 204 functional KAT vectors and deterministic signature verification for ML-DSA-65 and ML-DSA-87.
    - `test_kat_main.c`: Dedicated test runner executable (`rivide_kat_tests`).
  - Integrated dedicated build and execution targets (`make kat` and `make run-kat`), as well as CTest integration (`ctest -R rivide_kat_tests`).
- **Dedicated LLVM libFuzzer Fuzzing Subsystem**:
  - Implemented modular, mutation-based fuzz testing targets under [`fuzz/`](fuzz/) targeting parser boundaries, untrusted deserialization, and decoding edge cases:
    - `fuzz_ml_kem_decaps.c`: Fuzzes ML-KEM ciphertext deserialization, polynomial decompression, and implicit rejection pathways.
    - `fuzz_ml_dsa_verify.c`: Fuzzes ML-DSA signature length validation, hint vector unpacking, challenge recovery, and verification logic.
    - `fuzz_aes_gcm.c`: Fuzzes AES-128/256-GCM authenticated decryption, AAD processing, and GHASH tag authentication against random bit corruptions.
    - `fuzz_sha3.c`: Fuzzes SHA-3 one-shot hashing and SHAKE-128/256 incremental absorption/squeezing state transitions.
  - Added `make fuzz CC=clang` build target and CMake `RIVIDE_BUILD_FUZZERS` option with integrated AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.
- **Dedicated First-Class Benchmark Subsystem**:
  - Implemented an isolated performance profiling and throughput benchmark suite under [`benchmarks/`](benchmarks/):
    - `bench_harness.h`: High-resolution monotonic timer (`clock_gettime(CLOCK_MONOTONIC)` / `QueryPerformanceCounter`), compiler detection, and CPU acceleration feature query helper.
    - `bench_kem.c`: Operations/sec and microsecond latency benchmarking for ML-KEM-768 and ML-KEM-1024 KeyGen, Encaps, and Decaps.
    - `bench_dsa.c`: Operations/sec and microsecond latency benchmarking for ML-DSA-65 and ML-DSA-87 KeyGen, Sign, and Verify.
    - `bench_crypto.c`: High-throughput benchmarking (MB/sec and us/op) for SHA3-256, SHAKE-256, and AES-256-GCM AEAD over 4KB payload blocks.
    - `bench_main.c`: Configurable iteration runner via CLI arguments or `BENCH_ITERS` environment variable.
  - Added standalone build and run targets (`make bench` and `make run-bench`).
- **Documentation Expansion & Architectural Specifications**:
  - Added [`docs/architecture/testing_and_kat.md`](docs/architecture/testing_and_kat.md) documenting multi-tier test methodology and KAT layout.
  - Added [`docs/architecture/fuzzing.md`](docs/architecture/fuzzing.md) detailing libFuzzer design, target specifications, and execution instructions.
  - Added [`docs/architecture/benchmarking.md`](docs/architecture/benchmarking.md) documenting performance measurement methodology, hardware capability bitmasks, and metric reporting.
  - Synchronized API references in [`docs/api/core.md`](docs/api/core.md), [`docs/api/crypto_utils.md`](docs/api/crypto_utils.md), and [`docs/api/ntt_simd.md`](docs/api/ntt_simd.md).

### Changed
- **Benchmark Subsystem Relocation**:
  - Removed deprecated benchmark executable `examples/benchmark/pqc_bench.c` and migrated all profiling logic into the dedicated top-level `benchmarks/` subsystem.
- **Documentation Centralization**:
  - Consolidated sub-directory documentation (`fuzz/README.md`) into `docs/architecture/fuzzing.md`, establishing `docs/` as the single authoritative documentation tree.
- **Strict POSIX Feature Macro Compliance**:
  - Enforced `-D_POSIX_C_SOURCE=200809L` across all GNU and Clang build pipelines in `CMakeLists.txt` for consistent POSIX monotonic timer resolution.
- **Repository `.gitignore` Hygiene**:
  - Expanded root `.gitignore` to comprehensively ignore all CMake build variants (`build-*/`), test executables (`rivide_kat_tests`, `rivide_bench`), fuzzer targets (`fuzz_*`), fuzzing corpora (`corpus*/`), and sanitizer crash artifacts (`crash-*`, `leak-*`, `timeout-*`, `oom-*`).

### Security & Architecture Hardening
- **Randomness Subsystem OS CSPRNG Conformance Audit**:
  - Audited `src/utils/random.c` to guarantee strict OS-level CSPRNG entropy sources:
    - Linux: `getrandom(2)` with partial read loop handling `EINTR`.
    - macOS / BSD / iOS: `getentropy(2)` with 256-byte chunking.
    - Windows: `BCryptGenRandom` using `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
    - Freestanding / Embedded: Explicit `RIVIDE_ERR_RNG_FAILURE` return with zero insecure PRNG fallback (`rand()`, `lrand48()`).
  - Documented cryptographic randomness security guarantees in [`docs/architecture/memory_random.md`](docs/architecture/memory_random.md).
- **Public API Caller-Buffer Allocation Enforcement**:
  - Verified 100% caller-allocated memory model (`0% malloc`) across all public APIs (`include/rivide/`).
  - Guaranteed zero heap fragmentation, zero hidden background allocations, and const-correct input buffers across all exported functions.
- **Continuous Sanitizer & Static Analysis Conformance**:
  - Verified 100% clean passes with AddressSanitizer (`-fsanitize=address`), UndefinedBehaviorSanitizer (`-fsanitize=undefined`), `clang-format`, and `clang-tidy` across all library targets, tests, KAT vectors, examples, and benchmarks.

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
