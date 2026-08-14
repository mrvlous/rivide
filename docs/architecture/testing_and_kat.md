# NIST Known Answer Test (KAT) & Testing Subsystem

This document describes Rivide's automated testing infrastructure and official NIST Known Answer Test (KAT) validation subsystem.

## Testing Philosophy

Rivide enforces a multi-tiered verification pipeline designed to ensure cryptographic correctness, mathematical invertibility, side-channel resistance, and strict standard conformance:

1. **Unit Test Suite (`tests/`)**:
   - Comprehensive test cases covering functional roundtrips, invalid ciphertext rejection, tampered signatures, and constant-time selectors.
   - Run via `make test` or `ctest -R rivide_tests`.

2. **NIST Known Answer Test (KAT) Suite (`tests/kat/`)**:
   - Validates implementation against official NIST Cryptographic Algorithm Validation Program (CAVP) test vectors.
   - Run via `make kat` or `./build/rivide_kat_tests`.

3. **LLVM libFuzzer Fuzzing Suite (`fuzz/`)**:
   - Continuous mutation-based fuzzing of parser boundaries and decoding functions.
   - Built via `make fuzz CC=clang`.

4. **AddressSanitizer (ASan) & UndefinedBehaviorSanitizer (UBSan)**:
   - Zero tolerance for memory leaks, out-of-bounds reads/writes, or undefined integer arithmetic.

## NIST KAT Subsystem Layout

```
tests/kat/
├── test_kat_harness.h   # Hex conversion, assert macros, and test runner harness
├── test_kat_main.c      # Standalone KAT execution entry point
├── test_kat_sha3.c      # NIST FIPS 202 CAVP vectors for SHA-3 and SHAKE
├── test_kat_ml_kem.c    # NIST FIPS 203 KAT vectors for ML-KEM-768 and ML-KEM-1024
└── test_kat_ml_dsa.c    # NIST FIPS 204 KAT vectors for ML-DSA-65 and ML-DSA-87
```

## Running KAT in CI/CD

The KAT suite is designed for zero-dependency execution across Linux, macOS, and Windows environments:

```bash
# Build and execute the KAT suite
make kat

# Or via CMake build directory directly
./build/rivide_kat_tests
```
