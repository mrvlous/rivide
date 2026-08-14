# Automated Fuzzing Subsystem Architecture

This document details the design, configuration, and execution of automated fuzz testing using [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) in **Rivide**.

## Design Goals

1. **Isolation from Production Code**: Fuzz targets reside under `fuzz/` and are only compiled when `-DRIVIDE_BUILD_FUZZERS=ON` or `make fuzz` is specified.
2. **Boundary & Malformed Input Testing**: Focus on ciphertext decoding, signature deserialization, polynomial decompression, and authenticated AEAD tag verification with random and adversarial bit patterns.
3. **Continuous Sanitizer Conformance**: Fuzzers are compiled with `-fsanitize=fuzzer,address,undefined -g` to immediately trap memory safety violations, out-of-bounds reads, or undefined behavior.

## Fuzz Targets Specification

| Target File | Subsystem Under Test | Primary Security Focus |
| :--- | :--- | :--- |
| `fuzz/fuzz_ml_kem_decaps.c` | ML-KEM-768 & ML-KEM-1024 | Ciphertext deserialization, polynomial decompression, constant-time implicit rejection |
| `fuzz/fuzz_ml_dsa_verify.c` | ML-DSA-65 & ML-DSA-87 | Signature buffer length validation, hint unpacking, challenge recovery |
| `fuzz/fuzz_aes_gcm.c` | AES-128/256-GCM & GHASH | Authenticated tag validation, AAD handling, block parsing |
| `fuzz/fuzz_sha3.c` | SHA-3 & SHAKE-128/256 | Sponge permutation absorption, streaming state transitions |

## Directory Layout

```
fuzz/
├── fuzz_ml_kem_decaps.c  # ML-KEM decapsulation fuzzer
├── fuzz_ml_dsa_verify.c  # ML-DSA signature verification fuzzer
├── fuzz_aes_gcm.c        # AES-GCM AEAD decryption fuzzer
└── fuzz_sha3.c           # SHA-3 and SHAKE streaming fuzzer
```

## Compiling and Running Fuzzers

### Building with Clang

```bash
# Using Makefile
make fuzz CC=clang

# Or using CMake directly
cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DRIVIDE_BUILD_FUZZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz
```

### Running Fuzz Targets

Execute the generated binary directly. Specify duration or maximum runs as needed:

```bash
# Run ML-KEM decapsulation fuzzer for 60 seconds
./build-fuzz/fuzz_ml_kem_decaps -max_total_time=60

# Run ML-DSA verification fuzzer with 1,000,000 iterations
./build-fuzz/fuzz_ml_dsa_verify -runs=1000000

# Run AES-GCM fuzzer with corpus directory
mkdir -p corpus_gcm
./build-fuzz/fuzz_aes_gcm corpus_gcm/ -max_total_time=30

# Run SHA-3 fuzzer
./build-fuzz/fuzz_sha3 -max_total_time=30
```
