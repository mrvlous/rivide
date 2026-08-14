# Rivide Documentation Portal

Welcome to the official documentation for the **Rivide Post-Quantum Cryptography Library** (`v1.1.0`). Rivide is a high-performance, zero-dependency, constant-time C99 cryptographic library implementing NIST FIPS 203 (ML-KEM) and NIST FIPS 204 (ML-DSA).

## Documentation Structure

The documentation is organized into modular sections covering architecture, API references, integration guides, and developer contribution standards:

### Architecture Specs
- [Architecture Overview](architecture/overview.md): High-level system design, modular layering, and zero-allocation memory model.
- [ML-KEM Architecture](architecture/pqc_ml_kem.md): NIST FIPS 203 key encapsulation mechanism internals and polynomial arithmetic.
- [ML-DSA Architecture](architecture/pqc_ml_dsa.md): NIST FIPS 204 digital signature algorithm internals and Dilithium rejection sampling.
- [Symmetric Primitives Architecture](architecture/crypto_primitives.md): Keccak-f[1600], SHA-3, SHAKE, AES-GCM, and GHASH engines.
- [Memory & Randomness Architecture](architecture/memory_random.md): Secure memory cleansing, constant-time primitives, and OS entropy sources.
- [SIMD Acceleration Architecture](architecture/pqc_simd_ntt.md): Hardware vectorization (AVX2, ARM NEON, AES-NI) abstractions.
- [NIST KAT & Test Suite](architecture/testing_and_kat.md): Modular Known Answer Test framework and validation vectors.
- [Fuzzing Subsystem](architecture/fuzzing.md): Automated security fuzzing via LLVM libFuzzer.
- [Dedicated Benchmark Subsystem](architecture/benchmarking.md): Hardware performance measurement and metrics.

### API Reference
- [Core API](api/core.md): Initialization, error codes (`rivide_status_t`), and memory utilities.
- [ML-KEM API](api/ml_kem.md): KeyGen, Encapsulation, and Decapsulation routines for ML-KEM-768 and ML-KEM-1024.
- [ML-DSA API](api/ml_dsa.md): KeyGen, Signing, and Verification routines for ML-DSA-65 and ML-DSA-87.
- [Symmetric & Utility API](api/crypto_utils.md): SHA-3, SHAKE, AES-GCM, and constant-time memory helpers.
- [SIMD API](api/ntt_simd.md): Hardware feature detection queries and SIMD vector math functions.

### Integration Use Cases
- [Post-Quantum TLS 1.3](use_cases/network_tls.md): Hybrid PQC key exchange and identity certificate signing for network protocols.
- [Secure Vault Storage](use_cases/cloud_storage.md): Encrypted cloud/file vault containers using ML-KEM-1024 + AES-256-GCM + SHA3-512.
- [Embedded & IoT Security](use_cases/embedded_iot.md): Zero-heap bare-metal integration for resource-constrained microcontrollers.
- [Post-Quantum Web Tokens](use_cases/web_jwt.md): Quantum-safe API authentication and token signing using ML-DSA.

### Developer & Contribution Guides
- [Environment Setup](contributing/setup.md): Prerequisites and toolchain configuration (CMake, GCC/Clang, clang-format).
- [Build System & Benchmarking Guide](contributing/build.md): In-depth guide to compilation options, CMake parameters, Makefile targets, and `make bench`.
- [Coding Style Guide](contributing/style.md): ISO C99 compliance rules, Doxygen tagging standards, and memory safety rules.
