<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# NIST FIPS 202: SHA-3 and Keccak-f[1600] Sponge Specification

This document details the Keccak permutation engine and hash/XOF primitive implementations in **Rivide**.

## 1. Keccak Sponge Construction

The sponge construction operates on a 1600-bit state organized as a $5 \times 5$ array of 64-bit lanes:

$$\text{State} = A[x, y] \in \{0, 1\}^{64}, \quad x, y \in \{0, 1, 2, 3, 4\}$$

The total state size $b = 1600$ is divided into:
- **Bitrate ($r$)**: Data absorption block size.
- **Capacity ($c$)**: Security parameter ($r + c = 1600$).

## 2. Supported Hash and XOF Primitives

| Function | Bitrate ($r$) | Capacity ($c$) | Output Size | NIST Specification |
| :--- | :--- | :--- | :--- | :--- |
| **SHA3-256** | `1088` bits (136 bytes) | `512` bits | 32 bytes | Fixed-length message digest |
| **SHA3-512** | `576` bits (72 bytes) | `1024` bits | 64 bytes | High-security fixed-length digest |
| **SHAKE-128** | `1344` bits (168 bytes) | `256` bits | Arbitrary ($d$ bytes) | Extendable-output function (XOF) |
| **SHAKE-256** | `1088` bits (136 bytes) | `512` bits | Arbitrary ($d$ bytes) | XOF used for lattice sampling |

## 3. Keccak-f[1600] Permutation Rounds

Each of the 24 permutation rounds consists of 5 step mappings:

1. **$\theta$ (Theta)**: XOR sum of 5-lane columns with adjacent columns.
2. **$\rho$ (Rho)**: Bitwise cyclical rotation of individual 64-bit lanes.
3. **$\pi$ (Pi)**: Permutation of the 25 lane positions within the $5 \times 5$ grid.
4. **$\chi$ (Chi)**: Non-linear bitwise mixing using AND and XOR gates.
5. **$\iota$ (Iota)**: XORing round constants into the origin lane $A[0, 0]$ to break round symmetry.
