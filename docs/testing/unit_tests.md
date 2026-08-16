<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Testing: Automated Unit Testing & Differential Verification Framework

Documentation for the unit test suite, assertion harness, and differential testing against NIST reference implementations in **Rivide**.

## 1. Execution

```bash
make test
```

Or via CTest:

```bash
cd build && ctest --output-on-failure
```

## 2. Test Suite Coverage

- **`test_ml_kem.c`**: KeyGen, encapsulation, decapsulation roundtrip, and implicit rejection validation on corrupted ciphertexts.
- **`test_ml_dsa.c`**: KeyGen, signing, and verification roundtrip, and tamper rejection on modified messages or signatures.
- **`test_ntt.c`**: Forward and inverse NTT invertibility, linearity, and point-wise multiplication correctness.
- **`test_sha3.c`**: Known NIST test vectors for SHA3-256/512 and SHAKE-128/256.
- **`test_aes_gcm.c`**: Known NIST vectors for AES-128-GCM and AES-256-GCM authenticated encryption and authentication failure rejection.
- **`test_mem.c`**: Constant-time memory comparison (`rivide_ct_memcmp`), selection (`rivide_ct_select`), and zeroization barrier validation.

## 3. Differential Testing Methodology

Rivide utilizes differential fuzzing and cross-testing against the official NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) reference C implementations:
1. **Identical Seed Determinism**: Both implementations are seeded with identical 32-byte pseudo-entropy buffers.
2. **Intermediate State Differential Check**: Verifies that polynomial vectors, matrix expansions $\mathbf{A}$, CBD error distributions, NTT transformations, and packing formats match byte-for-byte at every cryptographic stage.
3. **Implicit Rejection Invariant**: Asserts that decapsulating a modified ciphertext produces identical pseudorandom fallback keys $K = \text{SHAKE256}(z \mathbin{\Vert} c)$ across implementations.
