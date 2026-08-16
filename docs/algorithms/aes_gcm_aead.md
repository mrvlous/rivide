<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# NIST SP 800-38D: AES-GCM Authenticated Encryption Specification

This document details the **Galois/Counter Mode (GCM)** authenticated encryption with associated data (AEAD) implementation in **Rivide**.

## 1. AEAD Security Goals

AES-GCM provides two simultaneous cryptographic guarantees:
1. **Confidentiality**: Plaintext is encrypted using AES in Counter (CTR) mode.
2. **Authenticity & Integrity**: Authenticates both ciphertext and unencrypted Additional Authenticated Data (AAD) using universal hashing over the finite field $\text{GF}(2^{128})$ via GHASH.

## 2. Supported Ciphers

| Algorithm | Key Size | Recommended IV Size | Tag Size | Standard |
| :--- | :--- | :--- | :--- | :--- |
| **AES-128-GCM** | 16 bytes (128 bits) | 12 bytes (96 bits) | 16 bytes (128 bits) | NIST SP 800-38D |
| **AES-256-GCM** | 32 bytes (256 bits) | 12 bytes (96 bits) | 16 bytes (128 bits) | NIST SP 800-38D |

## 3. GHASH Field Arithmetic in $\text{GF}(2^{128})$

GHASH computes a universal hash over 128-bit blocks using multiplication modulo the irreducible polynomial:

$$f(X) = X^{128} + X^7 + X^2 + X + 1$$

Given the hash subkey $H = \text{AES}_K(0^{128})$:

$$Y_i = (Y_{i-1} \oplus X_i) \cdot H \pmod{f(X)}$$

The final authentication tag $T$ is computed by encrypting the initial counter block and XORing with the GHASH output:

$$T = \text{GHASH}_H(\text{AAD} \parallel \text{Ciphertext} \parallel \text{Lengths}) \oplus \text{AES}_K(J_0)$$
