<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **`rivide`** Node.js native package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 2026-08-17

### Fixed

- **AES-GCM In-Flight Release of Unverified Plaintext (RUP) Prevention**:
    - Reordered authentication tag verification before CTR decryption in Node.js AES-GCM native routines (`js_aes_gcm_decrypt_internal`), ensuring caller buffers are never populated with unverified plaintext in-flight.
    - Preserves exact in-place buffer operations without premature buffer destruction on authentication failure.
- **Node-API Memory Hygiene & Heap Buffer Sanitization**:
    - Guaranteed explicit `rivide_cleanse` volatile memory zeroization on all temporary heap-allocated working buffers before calling `free()` in `napi_crypto.c` (across AES-GCM encryption/decryption and SHAKE-128/256 routines).
- **NIST FIPS 203 Section 7.3 Decapsulation Type Check**:
    - Bound ML-KEM secret key decoding to validate canonical polynomial coefficients ($\hat{s} < 3329$), throwing structured `ERR_INVALID_PARAM` errors on malformed secret keys.

## [1.1.3] - 2026-08-17

### Fixed

- **Table-Free Constant-Time Algebraic AES S-Box**:
    - Eliminated table lookups in AES transformations, evaluating S-box algebraically in GF(2^8) in constant time to eliminate cache-timing attacks.
- **NIST SP 800-38D Length Bounds & Buffer Overlap Validation**:
    - Added strict validation for payload length, AAD length, and partial buffer overlap in `aesGcm` routines.

## [1.1.2] - 2026-08-16

### Fixed

- **Constant-Time Branchless GHASH Multiplication**:
    - Replaced conditional branches in GHASH bitwise multiplication with constant-time bitmask arithmetic to prevent side-channel timing and branch predictor leakage.
- **Input Validation for AAD in AES-GCM**:
    - Added strict null pointer validation when `aad_len > 0` in authenticated encryption/decryption routines.
- **NIST FIPS 203 Section 7.2 Type Check in ML-KEM**:
    - Validated encapsulation key coefficients (< 3329) to reject malformed public keys.
- **Resilient CSPRNG Entropy Reads**:
    - Added `EINTR`/`EAGAIN` retry handling for Linux `getrandom(2)`.
- **Complete Secret Stack Zeroization**:
    - Zeroized intermediate polynomials and hash buffers across ML-KEM and ML-DSA.

## [1.1.1] - 2026-08-16

### Fixed

- **Thread-Safe Atomic RNG Synchronization**:
    - Synchronized underlying C custom entropy callbacks using C11 atomic acquire-release semantics for multi-threaded Node.js Worker Threads (`piscina`, `worker_threads`, cluster workers).
    - Guarantees zero data races during concurrent asynchronous key generation across worker threads.

### Added

- **Constant-Time Statistical Timing Verification**:
    - Verified constant-time execution for ML-KEM decapsulation and constant-time memory comparison (`utils.ctMemcmp`) using the Dudect Welch's t-test methodology ($|t| < 4.5$).
    - Added dedicated Makefile targets `make timing` and `make node-publish`.

### Security

- **Concurrency & Timing Attack Hardening**:
    - Validated statistical timing leakage boundaries across Node.js runtime bindings.
    - Documented formal concurrency guarantees and worker thread safety invariants.

### Documentation

- **API & Benchmark Guides**:
    - Updated Node.js API references and TypeScript declarations (`index.d.ts`) to version `1.1.1`.
    - Added publishing instructions for npm registry and multi-platform compilation guides.

## [1.1.0] - 2026-08-14

### Added

- **Initial Release of Official Node.js Native Bindings (`rivide`)**:
    - Direct, zero-dependency Node-API (N-API) C99 native integration with the Rivide Post-Quantum Cryptography engine.
- **NIST Post-Quantum Cryptography Modules**:
    - `mlKem768`: ML-KEM-768 keypair generation (`keypair`), encapsulation (`encaps`), and constant-time decapsulation (`decaps`).
    - `mlKem1024`: ML-KEM-1024 keypair generation (`keypair`), encapsulation (`encaps`), and constant-time decapsulation (`decaps`).
    - `mlDsa65`: ML-DSA-65 keypair generation (`keypair`), signing (`sign`), and strict signature verification (`verify`).
    - `mlDsa87`: ML-DSA-87 keypair generation (`keypair`), signing (`sign`), and strict signature verification (`verify`).
- **Symmetric Cryptography & Utility Modules**:
    - `sha3`: SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 extendable-output hashing.
    - `aesGcm`: AES-128-GCM and AES-256-GCM authenticated encryption and decryption.
    - `utils`: Secure memory zeroization (`cleanse`), OS CSPRNG entropy generation (`randombytes`), constant-time memory comparison (`ctMemcmp`), and runtime hardware SIMD feature detection (`getSimdCaps`).
- **Developer Ergonomics & Type Safety**:
    - Universal package manager compatibility supporting `npm`, `pnpm`, and `yarn` installations.
    - Full TypeScript declaration file (`index.d.ts`) with strict typing and JSDoc documentation.
    - Dual module distribution with CommonJS (`lib/index.js`) and ECMAScript Modules (`lib/index.mjs`).
    - Dedicated unit tests (`test/`) and interactive performance benchmark harness (`bench.js`).
