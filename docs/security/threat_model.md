<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security: Threat Model & Cryptographic Guarantees

This document establishes the adversary threat model, formal security definitions, and cryptographic boundaries of the **Rivide** library.

## 1. Adversary Capabilities & Security Goals

Rivide is designed under standard post-quantum cryptographic security models against active quantum-capable adversaries:

### ML-KEM: IND-CCA2 Security
- **Goal**: Indistinguishability under Adaptive Chosen-Ciphertext Attacks.
- **Guarantee**: An adversary who submits chosen ciphertexts to a decapsulation oracle cannot learn any non-trivial information regarding the encapsulated symmetric session key.
- **Protection**: Ensured via the implicit rejection mechanism of the **Fujisaki-Okamoto Transform** with pseudorandom failure tokens.

### ML-DSA: EUF-CMA Security
- **Goal**: Existential Unforgeability under Adaptive Chosen-Message Attacks.
- **Guarantee**: An adversary with access to a signing oracle cannot forge a valid signature for any message not explicitly queried to the oracle.
- **Protection**: Ensured via the **Fiat-Shamir with Aborts** lattice reduction to the M-SIS and M-LWE problems.

## 2. NIST Security Classification

| Scheme | NIST Level | Quantum Hardness | Classical Hardness | Equivalent Classical Primitive |
| :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | Category 3 | $\ge 2^{128}$ gates | $\ge 2^{192}$ operations | AES-192 key search |
| **ML-KEM-1024** | Category 5 | $\ge 2^{192}$ gates | $\ge 2^{256}$ operations | AES-256 key search |
| **ML-DSA-65** | Category 3 | $\ge 2^{128}$ gates | $\ge 2^{192}$ operations | AES-192 / SHA-384 collision |
| **ML-DSA-87** | Category 5 | $\ge 2^{192}$ gates | $\ge 2^{256}$ operations | AES-256 / SHA-512 collision |

## 3. Assumptions & Out-of-Scope Attacks

### In-Scope Security Hardening
- Timing side-channel attacks on secret keys and polynomials.
- Compiler dead-store optimization attacks on stack memory.
- Fault attacks via strict parameter and signature length validation.
- Classical and Shor's quantum algorithm attacks on lattice rings.

### Out-of-Scope Hardware Boundary Attacks
- Physical power analysis (DPA/SPA) requiring microarchitectural EM probe shielding.
- Microarchitectural CPU speculative execution attacks (e.g. Spectre/Meltdown variant mitigations are kernel/hardware responsibilities).
- Compromised host operating system CSPRNG (e.g. `/dev/urandom` corruption).

## 4. Concurrency & Multi-Threading Threat Model

Rivide is engineered for safe deployment in high-throughput concurrent environments, including Rust Rayon threadpools, Node.js Worker Threads, Go cgo goroutines, and POSIX pthreads.

### Thread-Safety Invariants

1. **Re-entrancy & Stateless Execution**:
   - All cryptographic routines (`rivide_ml_kem_*`, `rivide_ml_dsa_*`, `rivide_sha3_*`, `rivide_aes_gcm_*`) are purely stateless, thread-safe, and re-entrant.
   - Every operation executes exclusively on caller-provided buffers and local stack frames without global mutable state.
2. **Atomic RNG Callback Registration**:
   - Custom entropy callbacks registered via `rivide_set_rng_callback` are synchronized atomically via C11 `<stdatomic.h>` with release-acquire memory ordering.
   - Eliminates data races and torn pointer reads during concurrent key generation across worker threads.
3. **Thread-Local Volatile Memory Cleansing**:
   - Sensitive intermediate polynomial vectors and secrets are cleansed locally within each thread's stack frame prior to return, preventing cross-thread memory bleed.
