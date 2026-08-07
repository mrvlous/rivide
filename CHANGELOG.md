<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Changelog

All notable changes to the **Rivide** Post-Quantum Cryptography library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- AVX2 and ARM Neon SIMD vectorization for NTT polynomial transformations.
- Hardware acceleration detection extensions for AES-NI and ARM CE.

---

## [0.1.0] - 2026-08-06

### Added
- **NIST FIPS 203 ML-KEM Subsystem**:
  - Implemented ML-KEM-768 and ML-KEM-1024 Key Encapsulation Mechanism algorithms.
  - Added Number Theoretic Transform (NTT), inverse NTT, and Montgomery modular reduction ($q = 3329$).
  - Added Centered Binomial Distribution ($\mathrm{CBD}_\eta$) noise sampling engine.
  - Implemented Fujisaki-Okamoto (FO) transform with implicit rejection for decapsulation security.
- **NIST FIPS 204 ML-DSA Subsystem**:
  - Implemented ML-DSA-65 and ML-DSA-87 Digital Signature Algorithm parameters.
  - Added module-lattice polynomial vector arithmetic over $\mathbb{Z}_q[X]/(X^{256}+1)$ ($q = 8380417$).
  - Added rejection sampling signature generation loop with high/low coefficient decomposition (`Power2Round`, `Decompose`, `MakeHint`, `UseHint`).
- **Symmetric Cryptography Engine**:
  - Built-in Keccak-f[1600] 24-round state permutation engine (NIST FIPS 202).
  - Implemented SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 extendable-output functions (XOF).
  - Implemented software table-free constant-time AES-128/256-GCM AEAD encryption and GHASH authentication (NIST SP 800-38D).
- **Constant-Time & Memory Safety Primitives**:
  - Constant-time memory comparison (`rivide_ct_memcmp`) to prevent timing side-channel attacks.
  - Constant-time conditional buffer selection (`rivide_ct_select`).
  - Volatile memory zeroization barrier (`rivide_cleanse`) preventing compiler dead-store optimization.
  - Zero dynamic memory allocation (0% `malloc`) with caller-allocated stack buffers.
- **CSPRNG Entropy Engine**:
  - Multi-platform native kernel entropy dispatcher (`getrandom` on Linux, `BCryptGenRandom` on Windows).
  - Extensible custom random callback registration (`rivide_set_random_callback`).
- **Build System & Tooling Integration**:
  - ISO C99 strict standard compilation (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
  - Master CMake build system (`CMakeLists.txt`) with CTest integration (`enable_testing`).
  - Master Makefile (`Makefile`) automating `all`, `build`, `test`, `examples`, `run-examples`, `format`, `check-format`, `lint`, and `clean`.
  - IDE integration suite: `.clangd` (LSP compilation database), `.clang-format` (LLVM C99 style), `.clang-tidy` (static analysis), `.editorconfig`, `.gitattributes`, `.gitignore`.
- **Modular Documentation & GitHub Governance**:
  - Super modular documentation system in `docs/` (`architecture/*`, `api/*`, `contributing/*`).
  - GitHub Action Workflows (`.github/workflows/ci.yml`, `security.yml`, `release.yml`).
  - GitHub Issue Templates (`bug_report.md`, `feature_request.md`, `documentation.md`), PR template, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and `CODEOWNERS`.
  - Subsystem Maintainer mapping (`MAINTAINERS`) and Contributor acknowledgments (`CREDITS`).
