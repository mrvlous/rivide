<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Testing: LLVM libFuzzer Continuous Fuzzing

Documentation for coverage-guided continuous security fuzzing in **Rivide**.

---

## 1. Prerequisites & Compilation

Fuzzing targets require the Clang compiler with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):

```bash
make fuzz CC=clang
```

---

## 2. Fuzzing Target Binaries

| Target Binary | Subsystem Under Fuzzing | Target Function |
| :--- | :--- | :--- |
| `fuzz_ml_kem_decaps` | ML-KEM-768 / 1024 | Arbitrary malformed and crafted ciphertext decapsulation |
| `fuzz_ml_dsa_verify` | ML-DSA-65 / 87 | Arbitrary signature parsing and verification |
| `fuzz_aes_gcm` | AES-GCM AEAD | Malformed tag, IV, and payload parsing |
| `fuzz_sha3` | SHA-3 / SHAKE | Arbitrary length input stream absorption |

---

## 3. Running a Fuzzer

```bash
# Run ML-KEM decapsulation fuzzer with 1,000,000 iterations
./build-fuzz/fuzz_ml_kem_decaps -runs=1000000
```
