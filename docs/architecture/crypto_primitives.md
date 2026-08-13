# Symmetric Crypto Primitives Architecture

This document describes the design and implementation of Rivide's internal symmetric cryptographic primitives (Keccak-f[1600], SHA-3, SHAKE, AES-GCM, and GHASH).

## Keccak Permutation Engine & Sponge Construction

The core hash and extendable-output functions (XOF) are built on top of the 1600-bit Keccak-f permutation algorithm specified in NIST FIPS 202:

- **State Matrix**: 25 64-bit uint64_t lanes (200 bytes total).
- **Rounds**: 24 rounds executing $\theta, \rho, \pi, \chi, \iota$ transformations.
- **Sponge Bitrates**:
  - **SHA3-256**: Rate = 136 bytes (1088 bits), Capacity = 512 bits, Suffix = `0x06`.
  - **SHA3-512**: Rate = 72 bytes (576 bits), Capacity = 1024 bits, Suffix = `0x06`.
  - **SHAKE-128**: Rate = 168 bytes (1344 bits), Capacity = 256 bits, Suffix = `0x1F`.
  - **SHAKE-256**: Rate = 136 bytes (1088 bits), Capacity = 512 bits, Suffix = `0x1F`.

## AES-GCM Authenticated Encryption

Rivide provides hardware-accelerated and software fallback implementations of **AES-128-GCM** and **AES-256-GCM** per NIST SP 800-38D:

- **Key Schedules**: 10 rounds for AES-128, 14 rounds for AES-256.
- **GHASH Galois Field Multiplication**: Modular multiplication over $\mathbb{GF}(2^{128})$ with irreducible polynomial $f(x) = x^{128} + x^7 + x^2 + x + 1$.
- **Constant-Time Execution**: Table-free software GHASH and AES implementations prevent cache-timing attacks when hardware AES-NI or ARM Crypto extensions are unavailable.
