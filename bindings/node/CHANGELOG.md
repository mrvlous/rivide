<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **`rivide`** Node.js native package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
