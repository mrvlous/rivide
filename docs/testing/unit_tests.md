<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Testing: Automated Unit Testing Framework

Documentation for the unit test suite and assertion harness.

---

## 1. Execution

```bash
make test
```

Or via CTest:

```bash
cd build && ctest --output-on-failure
```

---

## 2. Test Suite Coverage

- **`test_ml_kem.c`**: KeyGen, encapsulation, decapsulation roundtrip, and implicit rejection validation on corrupted ciphertexts.
- **`test_ml_dsa.c`**: KeyGen, signing, and verification roundtrip, and tamper rejection on modified messages or signatures.
- **`test_ntt.c`**: Forward and inverse NTT invertibility, linearity, and point-wise multiplication correctness.
- **`test_sha3.c`**: Known NIST test vectors for SHA3-256/512 and SHAKE-128/256.
- **`test_aes_gcm.c`**: Known NIST vectors for AES-128-GCM and AES-256-GCM authenticated encryption and authentication failure rejection.
- **`test_mem.c`**: Constant-time memory comparison (`rivide_ct_memcmp`), selection (`rivide_ct_select`), and zeroization barrier validation.
