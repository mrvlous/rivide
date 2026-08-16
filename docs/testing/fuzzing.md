<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Testing: LLVM libFuzzer Continuous Fuzzing & Coverage

Documentation for coverage-guided continuous security fuzzing, sanitizer integration, and code coverage instrumentation in **Rivide**.

## 1. Prerequisites & Compilation

Fuzzing targets require the Clang compiler with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):

```bash
make fuzz CC=clang
```

Compiled with flags:
- `-fsanitize=fuzzer,address,undefined`
- `-fno-omit-frame-pointer -g -O1`
- `-fprofile-instr-generate -fcoverage-mapping` (for coverage reporting)

## 2. Fuzzing Target Binaries

| Target Binary | Subsystem Under Fuzzing | Target Function & Invariant Under Test |
| :--- | :--- | :--- |
| `fuzz_ml_kem_decaps` | ML-KEM-768 / 1024 | Arbitrary malformed and crafted ciphertext decapsulation and implicit rejection |
| `fuzz_ml_dsa_verify` | ML-DSA-65 / 87 | Arbitrary signature parsing, hint vector unpacking, and verification |
| `fuzz_aes_gcm` | AES-GCM AEAD | Malformed tag, IV, and payload parsing against authentication failures |
| `fuzz_sha3` | SHA-3 / SHAKE | Arbitrary length input stream absorption and permutation transitions |

## 3. Running Continuous Fuzzing & Corpus Management

```bash
# Run ML-KEM decapsulation fuzzer with 1,000,000 iterations
mkdir -p corpus_ml_kem
./build-fuzz/fuzz_ml_kem_decaps -runs=1000000 -max_len=2048 corpus_ml_kem/

# Run ML-DSA signature verification fuzzer
mkdir -p corpus_ml_dsa
./build-fuzz/fuzz_ml_dsa_verify -runs=1000000 -max_len=5000 corpus_ml_dsa/
```

## 4. Measuring Code Coverage with LLVM Coverage Tools

Generate detailed line-by-line coverage reports using `llvm-profdata` and `llvm-cov`:

```bash
# 1. Execute fuzzer over corpus to generate default.profraw
LLVM_PROFILE_FILE="fuzz_kem.profraw" ./build-fuzz/fuzz_ml_kem_decaps -runs=50000 corpus_ml_kem/

# 2. Merge raw profile data
llvm-profdata merge -sparse fuzz_kem.profraw -o fuzz_kem.profdata

# 3. Generate HTML coverage report
llvm-cov show ./build-fuzz/fuzz_ml_kem_decaps \
    -instr-profile=fuzz_kem.profdata \
    -format=html -output-dir=coverage_report/
```
