# Rivide Post-Quantum Cryptography Documentation Map

Welcome to the technical documentation for **Rivide**, a portable, zero-dependency C99 Post-Quantum Cryptography (PQC) library. This modular documentation system provides developers, cryptographers, and system integrators with a complete understanding of Rivide's design, architecture, API surfaces, and build ecosystem.

---

## Documentation Directory Layout

The documentation is organized into modular categories:

### 1. Architecture and Core Library Design
*   [Overview & Design Principles](architecture/overview.md): Architectural goals, C99 standard compliance, zero dynamic memory allocation, and constant-time side-channel mitigation techniques.
*   [ML-KEM (FIPS 203) Architecture](architecture/pqc_ml_kem.md): Mathematical foundations, polynomial ring $\mathbb{Z}_q[X]/(X^{256}+1)$, NTT transformations, Centered Binomial Distribution (CBD), and implicit rejection decapsulation for ML-KEM-768 and ML-KEM-1024.
*   [ML-DSA (FIPS 204) Architecture](architecture/pqc_ml_dsa.md): Module-lattice digital signatures over $\mathbb{Z}_q[X]/(X^{256}+1)$ with $q=8380417$, rejection sampling signing loop, hint vector packing, and verification algorithms for ML-DSA-65 and ML-DSA-87.
*   [Symmetric Cryptographic Primitives](architecture/crypto_primitives.md): Keccak-f[1600] permutation, SHA-3 and SHAKE sponge constructions (FIPS 202), and AES-128/256-GCM AEAD encryption (NIST SP 800-38D).
*   [Memory Cleansing & CSPRNG Entropy](architecture/memory_random.md): Secure memory zeroization via `rivide_cleanse` with compiler memory barriers, constant-time comparison primitives, and multi-platform CSPRNG entropy abstraction (Linux `getrandom`, Windows `BCryptGenRandom`, and bare-metal callbacks).

### 2. API References
*   [Core API Reference](api/core.md): Library initialization, runtime CPU feature detection, version reporting, and error handling status codes (`rivide_status_t`).
*   [ML-KEM API Reference](api/ml_kem.md): Keypair generation, key encapsulation, and decapsulation function signatures for ML-KEM-768 and ML-KEM-1024.
*   [ML-DSA API Reference](api/ml_dsa.md): Keypair generation, digital signature generation, and verification function signatures for ML-DSA-65 and ML-DSA-87.
*   [Symmetric Cryptography & Utility API Reference](api/crypto_utils.md): Direct APIs for SHA-3, SHAKE-128/256, AES-GCM AEAD encryption/decryption, memory cleansing, and random byte generation.

### 3. Contribution & Project Governance
*   [Development Environment Setup](contributing/setup.md): Installing required C toolchains (`gcc`/`clang`), CMake, `clang-format`, `clang-tidy`, and `clangd` LSP integration.
*   [Building, Testing & Tooling](contributing/build.md): Master build pipeline, CMake targets, unit testing (`ctest`), format checking (`make format`), and static analysis (`make lint`).
*   [Coding & License Style Guidelines](contributing/style.md): C99 coding standards, formatting rules, Doxygen comment conventions, and license header standardization.
*   [Version History & Changelog](../CHANGELOG.md): Complete release history and feature changelog.
*   [Subsystem Maintainers List](../MAINTAINERS): Maintainer roster, contact information, and subsystem path assignments.
*   [Project Contributors & Credits](../CREDITS): Acknowledgments for authors, contributors, and NIST standards bodies.
*   [GitHub Actions CI/CD](../.github/workflows/ci.yml): Automated continuous integration, CodeQL security scanning, and release workflows.
