<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Architecture Overview and Design Principles

The **Rivide** Post-Quantum Cryptography library is engineered from the ground up to provide high-performance, post-quantum security primitives in modern C99 for embedded, server, and system software applications.

---

## Core Design Goals

### 1. ISO C99 Standard Compliance
*   **Portability**: Written strictly in standard C99 (`set(CMAKE_C_STANDARD 99)`), avoiding compiler-specific language extensions (`set(CMAKE_C_EXTENSIONS OFF)`).
*   **Compiler Interoperability**: Fully compatible with GCC, Clang, MSVC, and bare-metal cross-compilers (e.g. ARM, RISC-V).

### 2. Zero External Dependencies
*   **Freestanding Ready**: Does not link against external cryptographic or utility libraries (such as OpenSSL or libsodium).
*   **Self-Contained Primitives**: Includes built-in implementations of Keccak (SHA-3 / SHAKE) and AES-GCM to fulfill NIST FIPS specifications autonomously.

### 3. Zero Dynamic Memory Allocation
*   **No Heap Dependability**: The core library never invokes `malloc`, `calloc`, `realloc`, or `free`.
*   **Caller-Allocated Buffers**: All state structures, key material, ciphertexts, and signatures use fixed sizes pre-allocated on the stack or caller-managed buffers.

### 4. Side-Channel Timing Resistance
*   **Constant-Time Arithmetic**: Modular polynomial operations, memory comparisons (`rivide_ct_memcmp`), and conditional selections (`rivide_ct_select`) execute in constant time relative to secret key values.
*   **Table-Free AES Fallback**: Standard C software AES implementation avoids precomputed T-table lookups to prevent cache-timing side-channel leaks on architectures without dedicated hardware acceleration (AES-NI / ARM CE).

---

## Directory and Subsystem Layout

```
rivide/
├── include/rivide/           # Public C API header definitions
│   ├── crypto/               # SHA-3 and AES-GCM module headers
│   ├── pqc/                  # ML-KEM and ML-DSA algorithm headers
│   └── utils/                # Constant-time memory and CSPRNG headers
├── src/                      # Internal library implementation files
│   ├── core/                 # Library initialization and status mappings
│   ├── crypto/               # Keccak-f[1600] and AES-GCM engine sources
│   ├── pqc/                  # ML-KEM (Kyber) and ML-DSA (Dilithium) logic
│   └── utils/                # Constant-time memory and CSPRNG sources
├── tests/                    # Unit testing harness and roundtrip tests
└── examples/                 # Demonstration programs (ML-KEM & ML-DSA)
```
