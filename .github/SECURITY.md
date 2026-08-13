<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security Policy

## Supported Versions

Only the latest release version on the `main` branch receives active security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

If you discover a potential security vulnerability, timing side-channel leak, memory safety issue, or cryptographic weakness in **Rivide**, please report it privately:

1. **Email**: Contact <mrvlous@proton.me> privately with details of the vulnerability.
2. **Details to Include**:
   - Description of the vulnerability or side-channel leakage vector.
   - Proof-of-concept code or step-by-step instructions to reproduce.
   - Affected API functions or source files (`src/pqc/*`, `src/crypto/*`, `src/utils/*`).
3. **Response Timeline**:
   - Initial acknowledgment: Within 48 hours.
   - Patch assessment & release: Within 14 days.
