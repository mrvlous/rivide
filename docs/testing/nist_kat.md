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

1. **SHA3-256 KAT**: Exact NIST CAVP message digest verification across standard test vector sets.
2. **SHA3-512 KAT**: Exact NIST CAVP 512-bit message digest validation.
3. **SHAKE-128 KAT**: Variable-length extendable-output function (XOF) CAVP validation.
4. **SHAKE-256 KAT**: Variable-length XOF CAVP validation.
5. **ML-KEM-768 KAT**: Exact keypair, ciphertext, and shared secret matching official NIST CAVP / FIPS 203 vectors.
6. **ML-KEM-1024 KAT**: Byte-exact validation for Category 5 parameters.
7. **ML-DSA-65 KAT**: Fixed-seed deterministic signature generation and validation matching NIST FIPS 204 vectors.
8. **ML-DSA-87 KAT**: Deterministic signature validation for Category 5 parameters.

## 3. Differential Reference Vector Comparison

All KAT vectors in [`tests/kat/`](../../tests/kat/) are derived directly from the official **NIST Cryptographic Algorithm Validation Program (CAVP)** and post-quantum reference distribution datasets.

Each test case:
- Parses pre-computed cryptographic test vector arrays containing hex-encoded seeds, message payloads, public keys, secret keys, ciphertexts, and signatures.
- Executes the Rivide implementation under fixed PRNG seeds.
- Asserts byte-exact equality across all resulting buffers using `rivide_ct_memcmp`.
