<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# ML-KEM Key Encapsulation Mechanism (NIST FIPS 203)

This document details the mathematical architecture, parameter sets, and implementation details of the **ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism) algorithm implemented in [`src/pqc/ml_kem.c`](../../src/pqc/ml_kem.c).

---

## 1. Overview

ML-KEM (standardized in NIST FIPS 203, based on the Kyber submission) provides IND-CCA2 secure key encapsulation derived from the hardness of the Module Learning With Errors (**MLWE**) problem in algebraic number theory.

Rivide supports two primary parameter sets:
*   **ML-KEM-768**: NIST Security Category 3 (AES-192 equivalent security level).
*   **ML-KEM-1024**: NIST Security Category 5 (AES-256 equivalent security level).

---

## 2. Mathematical Parameters & Ring Definition

ML-KEM operations take place over the polynomial quotient ring:
$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$
where:
*   Polynomial degree $n = 256$.
*   Prime modulus $q = 3329$.
*   Primitive 512th root of unity $\zeta = 17 \pmod q$.

### Parameter Set Comparison

| Parameter | ML-KEM-768 | ML-KEM-1024 | Description |
| :--- | :--- | :--- | :--- |
| **Module Rank ($k$)** | `3` | `4` | Number of polynomials per vector |
| **Public Key Size** | `1184` bytes | `1568` bytes | Encapsulation key size ($t \parallel \rho$) |
| **Secret Key Size** | `2400` bytes | `3168` bytes | Decapsulation key size ($s \parallel pk \parallel H(pk) \parallel z$) |
| **Ciphertext Size** | `1088` bytes | `1568` bytes | Encapsulated ciphertext ($c = u \parallel v$) |
| **Shared Secret** | `32` bytes | `32` bytes | Derived symmetric shared key |
| **CBD Noise ($\eta_1, \eta_2$)** | `2, 2` | `2, 2` | Centered Binomial Distribution parameters |
| **Compression ($d_u, d_v$)** | `10, 4` | `11, 5` | Bit-compression rates for ciphertext components |

---

## 3. Core Subsystems

### Number Theoretic Transform (NTT)
To perform efficient polynomial multiplication in $O(n \log n)$ time, polynomials are transformed into the NTT domain using the Cooley-Tukey butterfly algorithm:
*   **Forward NTT**: Converts coefficients from spatial domain into $128$ degree-1 NTT components using precomputed powers of $\zeta$.
*   **Inverse NTT**: Reverts NTT-domain polynomials using Gentleman-Sande butterflies and scales by $128^{-1} \pmod q$.
*   **Montgomery Reduction**: All modular multiplications use 16-bit Montgomery reduction ($R = 2^{16} \pmod q$, $q^{-1} \equiv 62209 \pmod{2^{16}}$) to eliminate explicit division operations.

### Centered Binomial Distribution (CBD)
Noise vectors $\mathbf{e}$ and secret vectors $\mathbf{s}$ are sampled using the Centered Binomial Distribution $\mathrm{CBD}_{\eta}$:
*   Generates coefficients in $[-\eta, \eta]$ by computing $\sum_{i=0}^{\eta-1} a_i - \sum_{i=0}^{\eta-1} b_i$ from uniform bitstreams provided by SHAKE-256 (PRF).

---

## 4. Key Encapsulation Workflow

### 1. Key Generation (`rivide_ml_kem_*_keygen`)
1. Sample 32 random bytes $d$ and 32 random bytes $z$ via CSPRNG.
2. Hash $G(d \parallel k) \to (\rho, \sigma)$.
3. Expand matrix $\mathbf{A} \in R_q^{k \times k}$ from seed $\rho$ using SHAKE-128 (ExpandA).
4. Sample secret vector $\mathbf{s}$ and noise vector $\mathbf{e}$ from $\sigma$ using $\mathrm{CBD}_{\eta_1}$.
5. Transform to NTT domain: $\hat{\mathbf{s}} = \mathrm{NTT}(\mathbf{s})$, $\hat{\mathbf{e}} = \mathrm{NTT}(\mathbf{e})$.
6. Compute public vector $\hat{\mathbf{t}} = \hat{\mathbf{A}} \circ \hat{\mathbf{s}} + \hat{\mathbf{e}}$.
7. Output $pk = (\hat{\mathbf{t}} \parallel \rho)$ and $sk = (\hat{\mathbf{s}} \parallel pk \parallel H(pk) \parallel z)$.

### 2. Encapsulation (`rivide_ml_kem_*_encaps`)
1. Sample 32 random bytes $m$.
2. Compute $(K, r) = G(m \parallel H(pk))$.
3. Encrypt message $m$ using randomness $r$ and public key $pk$ to produce ciphertext $c = (u \parallel v)$.
4. Output ciphertext $c$ and shared secret $K$.

### 3. Decapsulation (`rivide_ml_kem_*_decaps`)
1. Decrypt ciphertext $c$ using secret key vector $\hat{\mathbf{s}}$ to recover message $m'$.
2. Re-derive $(K', r') = G(m' \parallel H(pk))$.
3. Re-encrypt $m'$ under $pk$ with $r'$ to obtain re-encrypted ciphertext $c'$.
4. Perform constant-time comparison `cmp = rivide_ct_memcmp(c, c')`.
5. **Implicit Rejection**: If $c = c'$, return $K'$. If $c \neq c'$, return pseudorandom rejection value $J(z \parallel c)$ derived via SHAKE-256.
