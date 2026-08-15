# Rivide System Architecture Overview

This document provides a comprehensive technical overview of the **Rivide Post-Quantum Cryptography Library** architecture, module boundaries, memory management model, and design principles.

## Key Architectural Principles

Rivide is built around four core cryptographic engineering principles:

1. **Zero Dynamic Allocation (0 Malloc)**:
   - All data structures, polynomial vectors, keypair buffers, and state contexts are allocated strictly on the execution stack or provided by caller-owned memory buffers.
   - Eliminates heap fragmentation, memory leaks, use-after-free vulnerabilities, and non-deterministic dynamic allocation delays.

2. **Strict ISO C99 Standards Compliance**:
   - Written in pure, portable ISO C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
   - Standard fixed-width integer types (`uint8_t`, `uint32_t`, `int16_t`, `uint64_t`) from `<stdint.h>`.

3. **Constant-Time Execution**:
   - Secret key operations avoid secret-dependent conditional branches and secret-dependent memory indexing to prevent timing side-channel attacks.
   - Utilizes constant-time bitwise selectors (`rivide_ct_select`) and memory comparators (`rivide_ct_memcmp`).

4. **Modular Internal Architecture**:
   - Clear separation between public API boundaries (`include/rivide/`) and internal implementation headers (`include/rivide/internal/`).

## System Subsystem Layout

```
                  +-----------------------------------+
                  |        Public API Layer           |
                  |     (include/rivide/pqc/*.h)      |
                  +-----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
+-----------v-----------+                       +-----------v-----------+
|    ML-KEM Engine      |                       |    ML-DSA Engine      |
| (NIST FIPS 203 PKE)   |                       | (NIST FIPS 204 Sig)   |
+-----------+-----------+                       +-----------+-----------+
            |                                               |
            +-----------------------+-----------------------+
                                    |
                  +-----------------v-----------------+
                  |   Symmetric & Internal Utilities  |
                  | (Keccak, SHA-3, AES-GCM, SIMD)    |
                  +-----------------------------------+
```

## Source Code Organization

| Module Directory | Primary Responsibility |
| :--- | :--- |
| `include/rivide/` | Public API headers exported to library consumers. |
| `include/rivide/internal/` | Private header definitions for internal polynomial arithmetic and sampling. |
| `src/core/` | Global initialization, status codes, and type declarations. |
| `src/pqc/ml_kem/` | Modular implementation of ML-KEM-768 and ML-KEM-1024. |
| `src/pqc/ml_dsa/` | Modular implementation of ML-DSA-65 and ML-DSA-87. |
| `src/crypto/` | Symmetric primitives (Keccak, SHA-3, SHAKE, AES-GCM, GHASH). |
| `src/utils/` | Secure memory cleansing (`rivide_cleanse`) and OS entropy generation (`rivide_randombytes`). |
| `src/pqc/ntt_simd.c` | SIMD vector acceleration and hardware feature detection. |
| `benchmarks/` | Dedicated first-class performance profiling and benchmarking subsystem. |
| `fuzz/` | Dedicated LLVM libFuzzer automated security fuzzing subsystem. |
| `bindings/node/` | Official Node.js native Node-API (N-API) bindings and npm package (`rivide`). |
| `bindings/rust/` | Official Rust idiomatic bindings and crates.io crate (`rivide`). |

## Secure Memory Lifecycle

All sensitive cryptographic keys, intermediate polynomial coefficients, and sponge contexts are automatically cleansed using `rivide_cleanse` before functions return. This routine uses volatile pointer access to prevent compiler dead-store elimination optimizations.
