<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Testing: NIST Known Answer Test (KAT) & Reference Differential Validation

Documentation for the byte-exact validation framework and differential verification against official NIST cryptographic test vectors.

## 1. Execution

```bash
make kat
# or
./build/rivide_kat_tests
```

## 2. KAT Test Vectors Validated

1. **ML-KEM-768 KAT**: Exact keypair, ciphertext, and shared secret matching official NIST CAVP / FIPS 203 vectors.
2. **ML-KEM-1024 KAT**: Byte-exact validation for Category 5 parameters.
3. **ML-DSA-65 KAT**: Fixed-seed deterministic signature generation and validation matching NIST FIPS 204 vectors.
4. **ML-DSA-87 KAT**: Deterministic signature validation for Category 5 parameters.
5. **SHA-3 & SHAKE KAT**: Exact CAVP digest validation across standard test vectors.

## 3. Differential Reference Vector Comparison

All KAT vectors in [`tests/kat/`](../../tests/kat/) are derived directly from the official **NIST Cryptographic Algorithm Validation Program (CAVP)** and post-quantum reference distribution datasets.

Each test case:
- Parses pre-computed cryptographic test vector arrays containing hex-encoded seeds, message payloads, public keys, secret keys, ciphertexts, and signatures.
- Executes the Rivide implementation under fixed PRNG seeds.
- Asserts byte-exact equality across all resulting buffers using `rivide_ct_memcmp`.
