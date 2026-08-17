<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **Rivide** Post-Quantum Cryptography library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 2026-08-17

### Fixed
- **AES-GCM In-Flight RUP Prevention (SEC-01)**:
  - Reordered constant-time authentication tag verification prior to CTR mode decryption in `rivide_aes_gcm_decrypt`, preventing in-flight release of unverified plaintext (RUP) and preserving caller buffers in case of tag mismatch.
- **NIST FIPS 203 Section 7.3 Decapsulation Type Check (SEC-02)**:
  - Enforced strict validation on secret key polynomial coefficients (`s_hat < 3329`) in `ml_kem_decaps`, returning `RIVIDE_ERR_INVALID_PARAM` on corrupted or non-canonical secret keys.
- **Rust Key Lifecycle & RAII Cleansing (SEC-03)**:
  - Added explicit `rivide_aes_key_cleanse` zeroization across all `AesGcm` encryption and decryption methods.
- **Node-API Memory Sanitization (SEC-05)**:
  - Enforced `rivide_cleanse` zeroization of dynamic heap buffers before deallocation in AES-GCM and SHAKE routines.

## [1.1.3] - 2026-08-17

### Fixed
- **Table-Free Constant-Time Algebraic AES S-Box**:
  - Eliminated secret-dependent forward S-box table lookups (`aes_sbox[state[i]]`) in `src/crypto/aes_core.c`, replacing them with branchless, table-free constant-time algebraic multiplicative inversion in Galois Field GF(2^8) and affine bitwise transformations (`aes_sbox_ct`). Completely mitigates cache-timing, cache-collision, and microarchitectural side-channel vulnerabilities.
- **NIST SP 800-38D AES-GCM Length Bounds & Overflow Prevention**:
  - Enforced strict SP 800-38D length verification rejecting payloads exceeding 2^39 - 256 bits ((2^36 - 32) bytes) and AAD exceeding 2^64 - 1 bits (`UINT64_MAX / 8` bytes) with `RIVIDE_ERR_INVALID_PARAM`, preventing 64-bit length counter overflows and 32-bit counter wrapping.
- **AES-GCM Buffer Overlap & In-Place Safety**:
  - Explicitly permitted exact in-place authenticated encryption and decryption (`pt == ct`).
  - Added strict detection and rejection of partial overlapping buffers (`pt != ct` with intersecting memory ranges) and tag buffer collisions, returning `RIVIDE_ERR_INVALID_PARAM` instead of undefined behavior or corrupted state.
- **AES Key Material Lifecycle & Intermediate Zeroization**:
  - Added `@ref rivide_aes_key_cleanse` in `include/rivide/crypto/aes.h` and `src/crypto/aes_core.c` for explicit secure wiping of expanded round keys.
  - Guaranteed comprehensive `rivide_cleanse` zeroization of all intermediate secret buffers (`h`, `j0`, `counter`, `enc_block`, `ghash_tag`, `computed_tag`, `len_block`) on all return paths in AES-GCM.

### Added
- **Expanded Dudect Constant-Time Statistical Verification**:
  - Added dedicated statistical timing leakage test harnesses in [`tests/timing/test_dudect_kem.c`](tests/timing/test_dudect_kem.c) for AES block encryption, AES-256-GCM AEAD decryption, and GHASH GF(2^128) bitwise multiplications, formally asserting `|t| < 4.5`.
- **Automated Continuous Fuzzing (CI/CD)**:
  - Integrated dedicated `security-fuzzing` workflow job in GitHub Actions with LLVM libFuzzer, AddressSanitizer (ASan), and UndefinedBehaviorSanitizer (UBSan) covering ML-KEM decapsulation, ML-DSA verification, AES-GCM, and SHA-3.

## [1.1.2] - 2026-08-16

### Fixed
- **Constant-Time Branchless GHASH Multiplication**:
  - Eliminated conditional branching in Galois Field $\text{GF}(2^{128})$ bitwise multiplication (`rivide_ghash_mult`), replacing branches with constant-time bitmask arithmetic to prevent side-channel timing and branch predictor leakage of the secret GHASH key $H$.
- **Input Validation for AAD in AES-GCM**:
  - Added strict null pointer validation when `aad_len > 0` in `rivide_aes_gcm_encrypt` and `rivide_aes_gcm_decrypt`, preventing invalid GHASH length block encoding.
- **NIST FIPS 203 Section 7.2 Type Check Validation in ML-KEM**:
  - Implemented encapsulation key verification (`polyvec_frombytes_check`) ensuring all decoded polynomial coefficients in ByteDecode_12 are strictly $< 3329$ (`RIVIDE_ML_KEM_Q`), returning `RIVIDE_ERR_INVALID_PARAM` on malformed keys.
- **Linux CSPRNG Interruption Resilience**:
  - Added `EINTR` and `EAGAIN` retry handling in `rivide_os_randombytes` using `getrandom(2)` to prevent spurious RNG failures during POSIX signal interruptions.
- **SIMD Montgomery Modular Multiplication Parameterization**:
  - Bound `qinv` parameter in `rivide_simd_poly_pointwise_montgomery`, removing hardcoded reduction constants.
- **ML-DSA Signing Timeout Error Code**:
  - Corrected rejection loop timeout return code in `ml_dsa_sign_internal` from `RIVIDE_ERR_VERIFICATION_FAILED` to `RIVIDE_ERR_INTERNAL`.
- **Complete Intermediate Stack Variable Zeroization**:
  - Added `rivide_cleanse` zeroization for intermediate secret buffers (`msg_poly`, `v_poly`, `g_input`, `extseed`, `t0`, `cs2`, `ct0`, `w0`, `w`) across ML-KEM and ML-DSA.
- **Thread-Safe Atomic Library Initialization**:
  - Implemented atomic state management and compare-exchange synchronization in `rivide_init()`, eliminating data races during concurrent CPU feature detection.

## [1.1.1] - 2026-08-16

### Fixed
- **Thread-Safe Atomic Custom RNG Callback**:
  - Implemented atomic synchronization using C11 `<stdatomic.h>` (`atomic_store_explicit` / `atomic_load_explicit` with release-acquire semantics) and MSVC/GCC atomic intrinsics for `@ref rivide_set_rng_callback` and `@ref rivide_set_randombytes`.
  - Guarantees zero data races during concurrent multi-threaded entropy queries across Rust Rayon, Node.js Worker Threads, Go cgo, and POSIX pthreads.

### Added
- **Constant-Time Statistical Timing Leakage Verification Subsystem (Dudect)**:
  - Implemented standalone statistical test harness [`tests/timing/test_dudect_kem.c`](tests/timing/test_dudect_kem.c) based on the Dudect methodology and Welch's two-sample t-test.
  - Formally asserts $|t| < 4.5$ over 10,000+ iterations for ML-KEM-768 decapsulation (valid ciphertext vs corrupted ciphertext) and constant-time memory comparison (`rivide_ct_memcmp`).
  - Added master Makefile targets `make timing` and `make dudect`, and integrated `rivide_timing_tests` into CMake and CTest.

### Security
- **Side-Channel Hardening & Concurrency Threat Model**:
  - Validated statistical timing leakage boundaries using Welch's t-test ($|t| < 4.5$, corresponding to confidence $p > 10^{-5}$ for no timing leakage).
  - Documented formal concurrency guarantees and multi-threading execution boundaries in [`docs/security/threat_model.md`](docs/security/threat_model.md).

### Documentation
- **Testing & Security Assurance Guides**:
  - Updated [`docs/security/constant_time.md`](docs/security/constant_time.md) with detailed Dudect statistical verification methodology.
  - Enhanced [`docs/testing/fuzzing.md`](docs/testing/fuzzing.md) with LLVM coverage instrumentation (`llvm-cov`), continuous fuzzing duration standards, and ASan/UBSan configurations.
  - Enhanced [`docs/testing/unit_tests.md`](docs/testing/unit_tests.md) and [`docs/testing/nist_kat.md`](docs/testing/nist_kat.md) with differential testing explanations against NIST reference implementations.

## [1.1.0] - 2026-08-14

### Added
- **Dedicated NIST Known Answer Test (KAT) Subsystem**:
  - Implemented a standalone, modular KAT verification framework under [`tests/kat/`](tests/kat/) with reproducible byte-exact vector validation:
    - [`test_kat_harness.h`](tests/kat/test_kat_harness.h): Standardized KAT comparison macros, bitwise hex string parser, and result accounting.
    - [`test_kat_sha3.c`](tests/kat/test_kat_sha3.c): Official NIST FIPS 202 CAVP test vectors for SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 across empty, short, and multi-block inputs.
    - [`test_kat_ml_kem.c`](tests/kat/test_kat_ml_kem.c): NIST FIPS 203 functional KAT vectors and deterministic constant-time implicit rejection consistency checks for ML-KEM-768 and ML-KEM-1024.
    - [`test_kat_ml_dsa.c`](tests/kat/test_kat_ml_dsa.c): NIST FIPS 204 functional KAT vectors and deterministic signature verification for ML-DSA-65 and ML-DSA-87.
    - [`test_kat_main.c`](tests/kat/test_kat_main.c): Dedicated test runner executable (`rivide_kat_tests`).
  - Integrated dedicated build and execution targets (`make kat` and `make run-kat`), as well as CTest integration (`ctest -R rivide_kat_tests`).
- **Dedicated LLVM libFuzzer Fuzzing Subsystem**:
  - Implemented modular, mutation-based fuzz testing targets under [`fuzz/`](fuzz/) targeting parser boundaries, untrusted deserialization, and decoding edge cases:
    - [`fuzz_ml_kem_decaps.c`](fuzz/fuzz_ml_kem_decaps.c): Fuzzes ML-KEM ciphertext deserialization, polynomial decompression, and implicit rejection pathways.
    - [`fuzz_ml_dsa_verify.c`](fuzz/fuzz_ml_dsa_verify.c): Fuzzes ML-DSA signature length validation, hint vector unpacking, challenge recovery, and verification logic.
    - [`fuzz_aes_gcm.c`](fuzz/fuzz_aes_gcm.c): Fuzzes AES-128/256-GCM authenticated decryption, AAD processing, and GHASH tag authentication against random bit corruptions.
    - [`fuzz_sha3.c`](fuzz/fuzz_sha3.c): Fuzzes SHA-3 one-shot hashing and SHAKE-128/256 incremental absorption/squeezing state transitions.
  - Added `make fuzz CC=clang` build target and CMake `RIVIDE_BUILD_FUZZERS` option with integrated AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.
- **Dedicated First-Class Benchmark Subsystem**:
  - Implemented an isolated performance profiling and throughput benchmark suite under [`benchmarks/`](benchmarks/):
    - [`bench_harness.h`](benchmarks/bench_harness.h): High-resolution monotonic timer (`clock_gettime(CLOCK_MONOTONIC)` / `QueryPerformanceCounter`), compiler detection, and CPU acceleration feature query helper.
    - [`bench_kem.c`](benchmarks/bench_kem.c): Operations/sec and microsecond latency benchmarking for ML-KEM-768 and ML-KEM-1024 KeyGen, Encaps, and Decaps.
    - [`bench_dsa.c`](benchmarks/bench_dsa.c): Operations/sec and microsecond latency benchmarking for ML-DSA-65 and ML-DSA-87 KeyGen, Sign, and Verify.
    - [`bench_crypto.c`](benchmarks/bench_crypto.c): High-throughput benchmarking (MB/sec and us/op) for SHA3-256, SHAKE-256, and AES-256-GCM AEAD over 4KB payload blocks.
    - [`bench_main.c`](benchmarks/bench_main.c): Configurable iteration runner via CLI arguments or `BENCH_ITERS` environment variable.
  - Added standalone build and run targets (`make bench` and `make run-bench`).
- **Official Node.js Native Bindings & Package (`rivide`)**:
  - Implemented high-performance, zero-dependency Node-API (N-API) native bindings under [`bindings/node/`](bindings/node/) with full multi-package-manager support (`npm`, `pnpm`, `yarn`):
    - [`src/napi_kem.c`](bindings/node/src/napi_kem.c): ML-KEM-768 and ML-KEM-1024 keypair generation, encapsulation, and decapsulation.
    - [`src/napi_dsa.c`](bindings/node/src/napi_dsa.c): ML-DSA-65 and ML-DSA-87 digital signing and verification with strict `siglen` boundary validation.
    - [`src/napi_crypto.c`](bindings/node/src/napi_crypto.c): SHA-3, SHAKE-128/256 XOF, and AES-128/256-GCM authenticated encryption/decryption.
    - [`src/napi_utils.c`](bindings/node/src/napi_utils.c): Constant-time memory cleansing (`cleanse`), OS entropy generation (`randombytes`), and SIMD capability inspection (`getSimdCaps`).
  - Added comprehensive TypeScript type definitions ([`index.d.ts`](bindings/node/index.d.ts)), CommonJS ([`lib/index.js`](bindings/node/lib/index.js)), and ESM ([`lib/index.mjs`](bindings/node/lib/index.mjs)) dual module exports.
  - Added automated test suite (`npm test`), interactive performance benchmark (`npm run bench`), and demonstration examples under [`bindings/node/examples/`](bindings/node/examples/).
  - Added `make node-build`, `make node-test`, and `make node-bench` automation targets to master `Makefile`.
- **Official Rust Native Bindings & Crate (`rivide`)**:
  - Implemented idiomatic, zero-allocation Rust bindings under [`bindings/rust/`](bindings/rust/) with direct C99 compilation via `build.rs`:
    - Safe types for **ML-KEM-768** and **ML-KEM-1024** (`MlKem768`, `MlKem1024`, `MlKem768KeyPair`, `MlKem768EncapsResult`).
    - Safe types for **ML-DSA-65** and **ML-DSA-87** (`MlDsa65`, `MlDsa87`, `MlDsa65KeyPair`, `MlDsa65Signature`).
    - Symmetric cryptography wrappers for SHA-3, SHAKE-128/256, and AES-128/256-GCM AEAD (`Sha3`, `AesGcm`).
    - Automated RAII memory zeroization (`Drop` trait implementation invoking `rivide_cleanse` on all secret keys).
    - Fixed-size stack arrays (`[u8; N]`) for zero heap allocation overhead.
    - Automated integration tests (`tests/`) and standalone examples (`examples/`).
    - Added `make rust-build`, `make rust-test`, `make rust-examples`, and `make rust-bench` Makefile targets.
- **Documentation Expansion & Architectural Specifications**:
  - Added [`docs/architecture/node_bindings.md`](docs/architecture/node_bindings.md) documenting Node-API design and JavaScript runtime interface.
  - Added [`docs/architecture/rust_bindings.md`](docs/architecture/rust_bindings.md) documenting Rust crate design and RAII memory model.
  - Added [`docs/architecture/testing_and_kat.md`](docs/architecture/testing_and_kat.md) documenting multi-tier test methodology and KAT layout.
  - Added [`docs/architecture/fuzzing.md`](docs/architecture/fuzzing.md) detailing libFuzzer design, target specifications, and execution instructions.
  - Added [`docs/architecture/benchmarking.md`](docs/architecture/benchmarking.md) documenting performance measurement methodology, hardware capability bitmasks, and metric reporting.
  - Synchronized API references in [`docs/api/core.md`](docs/api/core.md), [`docs/api/crypto_utils.md`](docs/api/crypto_utils.md), and [`docs/api/ntt_simd.md`](docs/api/ntt_simd.md).

### Changed
- **Benchmark Subsystem Relocation**:
  - Removed deprecated benchmark executable `examples/benchmark/pqc_bench.c` and migrated all profiling logic into the dedicated top-level `benchmarks/` subsystem.
- **Documentation Centralization**:
  - Consolidated sub-directory documentation (`fuzz/README.md`) into `docs/architecture/fuzzing.md`, establishing `docs/` as the single authoritative documentation tree.
- **Cross-Platform Compilation Hardening**:
  - Defined `_DARWIN_C_SOURCE` on macOS in `CMakeLists.txt` to guarantee clean access to BSD system types (`u_int`) in `<sys/sysctl.h>`.
  - Defined `_POSIX_C_SOURCE=200809L` on UNIX/Linux systems in `CMakeLists.txt` for monotonic timer resolution.
  - Defined `_CRT_SECURE_NO_WARNINGS` on Windows MSVC in `CMakeLists.txt` to prevent C4996 warnings on `/WX`.
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

## [1.0.1] - 2026-08-14

### Fixed
- **Strict Signature Length Validation in ML-DSA (Security Audit P0 Remediation)**:
  - Enforced strict buffer length validation in [`rivide_ml_dsa_65_verify`](include/rivide/pqc/ml_dsa.h) and [`rivide_ml_dsa_87_verify`](include/rivide/pqc/ml_dsa.h) against expected encoded signature sizes (`RIVIDE_ML_DSA_65_SIG_BYTES = 3309`, `RIVIDE_ML_DSA_87_SIG_BYTES = 4627`).
  - Corrected internal signature deserialization in [`src/pqc/ml_dsa/ml_dsa.c`](src/pqc/ml_dsa/ml_dsa.c) to strictly reject both truncated (`siglen < expected`) and oversized (`siglen > expected`) signatures with `RIVIDE_ERR_VERIFICATION_FAILED` before deserialization, preventing out-of-bounds reads and undefined behavior.
- **Python CTypes FFI Binding (`examples/python/rivide_pqc_binding.py`)**:
  - Corrected function symbol from `rivide_ml_kem_768_keypair` to `rivide_ml_kem_768_keygen` to align with the public C library API header.

### Added
- **Security Regression & Boundary Fuzzing Test Suite**:
  - Added `test_ml_dsa_65_siglen_validation` and `test_ml_dsa_87_siglen_validation` in [`tests/pqc/test_ml_dsa.c`](tests/pqc/test_ml_dsa.c) testing signature length boundaries (`siglen = 0, 1, 2, expected-1, expected, expected+1, expected+32`).
  - Added `test_ml_dsa_boundary_fuzz` verifying robust rejection on corrupted challenge seeds ($c$), corrupted $z$ polynomials, corrupted hint vectors ($h$), corrupted public keys, NULL pointers, and empty messages (`msglen = 0`).
- **Mathematical NTT/INTT Invertibility & Modular Reduction Tests**:
  - Added `test_ml_kem_ntt_invertibility` in [`tests/pqc/test_ntt.c`](tests/pqc/test_ntt.c) verifying roundtrip invertibility of $\text{INTT}(\text{NTT}(x))$ modulo $q = 3329$.
  - Added `test_ml_dsa_ntt_invertibility` in [`tests/pqc/test_ntt.c`](tests/pqc/test_ntt.c) verifying roundtrip invertibility of $\text{INTT}(\text{NTT}(x))$ modulo $q = 8380417$.
  - Added `test_modular_reductions` verifying Barrett reduction and conditional modular addition ($q$).
- **Sanitizer Conformance Verification**:
  - Verified full test suite execution under AddressSanitizer (`-fsanitize=address`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`) with zero warnings, zero memory leaks, and zero undefined behaviors.

### Changed
- **API Documentation Updates**:
  - Updated [`docs/api/ml_dsa.md`](docs/api/ml_dsa.md) documenting explicit `siglen` buffer requirements and `RIVIDE_ERR_VERIFICATION_FAILED` error return code for ML-DSA verification functions.

## [1.0.0] - 2026-08-13

### Added
- **Initial Production-Ready Release (`v1.0.0`)**:
  - Official production release of the Rivide Post-Quantum Cryptography C99 library.
- **NIST Post-Quantum Cryptography Primitives**:
  - Implemented **NIST FIPS 203** Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
  - Implemented **NIST FIPS 204** Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
  - Implemented Fujisaki-Okamoto (FO) transform with constant-time implicit rejection for ML-KEM decapsulation.
- **Modular C99 Architecture & Clean Header Hierarchy**:
  - Modularized codebase into single-responsibility submodules (`src/core/`, `src/utils/`, `src/crypto/`, `src/pqc/ml_kem/`, `src/pqc/ml_dsa/`).
  - Separated public headers cleanly under `include/rivide/` (`core/`, `crypto/`, `pqc/`).
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
- **Granular Test Suite & Example Applications**:
  - Granular 14-test unit test suite executed via CTest (`make test`).
  - 7 standalone executable demonstration programs under `examples/` covering key exchange, digital signatures, hybrid AEAD, TLS 1.3 handshakes, secure vault storage, and Python CTypes FFI bindings.
- **Cross-Platform Tooling & Build System**:
  - Strict ISO C99 compliance (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
  - Master CMake build system (`CMakeLists.txt`) and master Makefile (`Makefile`).
  - IDE integration configuration files: `.clangd` (LSP), `.clang-format`, `.clang-tidy`, `.editorconfig`, `.gitattributes`, `.gitignore`.
