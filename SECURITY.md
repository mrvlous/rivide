<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security Policy & Audit Transparency

The Rivide project approaches post-quantum cryptographic engineering with radical honesty, mathematical rigor, and transparency.

## 1. Audit Status & Independent Implementation Notice

Rivide is an independent post-quantum cryptography library implemented strictly from the official, finalized National Institute of Standards and Technology specifications (**NIST FIPS 202**, **NIST FIPS 203**, and **NIST FIPS 204**).

> [!WARNING]
> **Independent Implementation Notice**:
> As of version **1.1.7**, Rivide has **NOT yet undergone a formal commercial third-party security audit** by an external security assessment firm (such as Trail of Bits, Cure53, NCC Group, or Quarkslab).

While the library is hardened against known side-channel vectors and passes comprehensive automated verification suites, cryptographic code inherently carries operational risks prior to external third-party evaluation. Organizations considering Rivide for high-consequence production infrastructure must assess this status within their risk management framework.

## 2. Verifiable Engineering & Safety Guarantees

To provide verifiable confidence prior to a commercial audit, Rivide implements rigorous defensive engineering principles that can be independently verified by any developer or auditor:

1. **100% NIST CAVP Known Answer Tests (KAT)**:
   - Every build validates 8 out of 8 official NIST test vectors covering SHA-3, SHAKE, ML-KEM-768/1024, and ML-DSA-65/87 (`make kat`).
   - Bit-level compatibility matches official NIST CAVP reference test suites exactly.
2. **Zero Dynamic Allocation (0 Malloc Memory Model)**:
   - The C core contains **zero calls to `malloc()`, `calloc()`, `realloc()`, or `free()`**.
   - Entire classes of high-severity C memory bugs (heap buffer overflow, use-after-free, double-free, heap layout manipulation) are structurally impossible.
3. **Statistical Constant-Time Verification (Dudect)**:
   - The test suite includes automated Dudect leakage detection executing Welch's two-sample $t$-test over 10,000 samples per primitive (`make timing`).
   - All critical paths satisfy $|t| \le 1.85 \ll 4.50$, mathematically rejecting secret-dependent timing leakage.
4. **Table-Free Algebraic GF(2^8) AES S-Box**:
   - The AES-128/256 subsystem computes S-Box substitutions using branchless tower field inversion in $GF(2^8)$ rather than memory lookup tables, eliminating cache-timing attacks.
5. **Continuous Sanitizer Verification (ASan & UBSan)**:
   - Automated builds with Clang AddressSanitizer and UndefinedBehaviorSanitizer (`make sanitize`) run with zero memory or undefined behavior warnings.
6. **Volatile Memory Scrubbing**:
   - All secret keys, polynomial vectors, and sponge states are scrubbed prior to function return using compiler barrier cleansing routines (`rivide_cleanse` and Rust RAII `Drop` traits).

## 3. Recommended Production Strategy: Hybrid Cryptography

Consistent with recommendations from international cybersecurity authorities (**NIST**, **BSI Germany**, and **ANSSI France**), we strongly recommend adopting a **Hybrid Cryptography Model** for production deployments during the post-quantum transition period:

- **Key Encapsulation**: Combine **ML-KEM-768** with classical authenticated encryption (**AES-256-GCM**) or classical ECDH (X25519).
- **Defense-in-Depth**: In a hybrid envelope, even if a mathematical breakthrough were to weaken a newly standardized lattice scheme, the classical cipher guarantees uninterrupted confidentiality.
- Rivide includes native AES-128/256-GCM directly alongside ML-KEM to facilitate hybrid secure channels without external dependencies.

## 4. Seeking Audit Sponsorship & Peer Review

We actively welcome academic scrutiny, independent peer reviews, and formal security analysis from the cryptographic community:

- **Audit Grants**: We are actively seeking sponsorship or grant support (such as from OSTIF - Open Source Technology Improvement Fund, NLnet Foundation, or corporate sponsors) to fund a commercial third-party audit.
- **Academic Research**: Researchers analyzing lattice arithmetic, NTT implementations, or constant-time bounds are invited to review our source code and share findings.

## 5. Vulnerability Reporting & Coordinated Disclosure

If you discover a security flaw, timing vulnerability, or cryptographic defect in Rivide, please report it responsibly:

- **Security Contact**: Moh. Ananda Firmansyah Putra
- **Email**: `mrvlous@proton.me`
- **PGP Key**: Available upon request for encrypted disclosure.

Please **do not disclose vulnerabilities publicly via GitHub issues** before a fix has been prepared and coordinated.

### Reporting Guidelines:
1. Provide a detailed summary of the vulnerability and affected components.
2. Include reproduction code, proof-of-concept (PoC), or environment details.
3. Allow up to 48 hours for initial acknowledgment.
4. Coordinated public release and CVE publication will occur once the patch is validated.

## 6. Security Hall of Fame

We gratefully acknowledge security researchers who have helped review, harden, or audit the Rivide codebase:

*(Contributions and security review credits will be memorialized here upon coordinated disclosure.)*
