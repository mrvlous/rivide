<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Getting Started: Overview of Rivide

**Rivide** is an enterprise-grade, high-performance Post-Quantum Cryptography (PQC) library engineered in pure ISO C99. It implements the finalized post-quantum standards established by the **National Institute of Standards and Technology (NIST)**:

- **NIST FIPS 203**: Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
- **NIST FIPS 202**: SHA-3 and SHAKE Extendable-Output Functions (**SHA3-256**, **SHA3-512**, **SHAKE-128**, **SHAKE-256**).
- **NIST SP 800-38D**: Galois/Counter Mode Authenticated Encryption with Associated Data (**AES-128-GCM** and **AES-256-GCM**).

---

## Why Post-Quantum Cryptography?

Modern public-key cryptographic infrastructure relies on mathematical hardness assumptions that can be solved in polynomial time by a sufficiently large quantum computer running **Shor's Algorithm**:

- **RSA (Rivest-Shamir-Adleman)**: Dependent on integer factorization.
- **ECDH / ECDSA (Elliptic-Curve Cryptography)**: Dependent on the discrete logarithm problem over elliptic curve groups.
- **Diffie-Hellman Key Exchange (DH)**: Dependent on the discrete logarithm problem over finite fields.

Once fault-tolerant quantum computers become reality, all historical and active communications secured with RSA and ECC will become readable via the **"Harvest Now, Decrypt Later"** strategy.

### The Lattice-Based Defense

Rivide implements lattice-based cryptographic schemes rooted in the hardness of the **Module Learning With Errors (M-LWE)** and **Module Short Integer Solution (M-SIS)** problems over polynomial quotient rings $\mathcal{R}_q = \mathbb{Z}_q[X]/(X^{256} + 1)$. These problems remain computationally intractable for both classical and quantum algorithms.

---

## Architectural Core Principles

1. **Strict ISO C99 Compliance**:
   - Written in 100% standard C99 without proprietary compiler extensions (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
2. **Zero Dynamic Allocation (0 Malloc)**:
   - Eliminates heap allocation completely (`malloc`, `calloc`, `free` are strictly prohibited). All state buffers reside on the stack or in caller-provided memory.
3. **Constant-Time Execution**:
   - All secret-dependent computations avoid conditional branching and data-indexed memory lookups to protect against cache-timing and execution-time side-channel attacks.
4. **Automated Memory Cleansing**:
   - Provides volatile memory barriers (`rivide_cleanse`) to prevent compiler dead-store elimination from skipping private key zeroization.
5. **Hardware SIMD Acceleration**:
   - Executes native 256-bit AVX2 and 128-bit ARM NEON vectorized Number Theoretic Transform (NTT) polynomial arithmetic.
6. **Multi-Language Native Ecosystem**:
   - First-class support for **C99**, **Node.js / TypeScript** (`rivide`), **Rust** (`rivide`), and **Python** (ctypes FFI).

---

## Quick Navigation

- [C99 Quickstart](quickstart_c.md): Compiling and linking Rivide in C/C++ projects.
- [Node.js / TypeScript Quickstart](quickstart_node.md): Using the `rivide` npm package.
- [Rust Quickstart](quickstart_rust.md): Using the `rivide` crates.io package.
- [Python Quickstart](quickstart_python.md): Dynamic loading via ctypes.
