<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# NIST FIPS 204: ML-DSA Algorithm Specification

This document provides the mathematical principles, parameter definitions, and signing/verification procedures for the **Module-Lattice-Based Digital Signature Algorithm (ML-DSA)** standard implemented in **Rivide**.

## 1. Mathematical Framework

ML-DSA operates over the polynomial quotient ring:

$$\mathcal{R}_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$

with modulus:

$$q = 8380417 = 2^{23} - 2^{13} + 1$$

The security of ML-DSA relies on the hardness of two related lattice problems:
- **Module Learning With Errors (M-LWE)**
- **Module Short Integer Solution (M-SIS)**

## 2. Parameter Sets

| Parameter | ML-DSA-65 | ML-DSA-87 | Description |
| :--- | :--- | :--- | :--- |
| **NIST Security Level** | Category 3 (AES-192) | Category 5 (AES-256) | Security classification |
| **Matrix Dimensions ($k \times l$)** | $6 \times 5$ | $8 \times 7$ | Dimensions of matrix $\mathbf{A} \in \mathcal{R}_q^{k \times l}$ |
| **Secret Bound ($\eta$)** | `4` | `2` | Bound on coefficients of $\mathbf{s}_1, \mathbf{s}_2$ |
| **$\gamma_1$ (Masking Parameter)** | $2^{19} = 524288$ | $2^{19} = 524288$ | Bound on coefficients of masking vector $\mathbf{y}$ |
| **$\gamma_2$ (Decomposition Bound)** | $(q - 1)/32 = 261888$ | $(q - 1)/32 = 261888$ | Low/high bit rounding divisor |
| **Commitment Bound ($\tau$)** | `49` | `60` | Number of $\pm 1$ coefficients in challenge $c$ |
| **$\beta$ (Rejection Bound)** | $196$ | $120$ | Rejection condition limit $\tau \cdot \eta$ |
| **$\omega$ (Max Hint Bits)** | `55` | `75` | Maximum count of non-zero hints in $\mathbf{h}$ |
| **Public Key Length** | `1952` bytes | `2592` bytes | Encoded $(\rho, \mathbf{t}_1)$ |
| **Secret Key Length** | `4032` bytes | `4896` bytes | Encoded $(\rho, K, \text{tr}, \mathbf{s}_1, \mathbf{s}_2, \mathbf{t}_0)$ |
| **Signature Length** | `3309` bytes | `4627` bytes | Encoded $(\tilde{c}, \mathbf{z}, \mathbf{h})$ |

## 3. Fiat-Shamir with Aborts Protocol

ML-DSA uses the **Fiat-Shamir with Aborts** paradigm to generate signatures without leaking private key coefficients via signature distribution:

```
     Signer                                                    Verifier
     ------                                                    --------
1. Sample y from S_{gamma_1}
2. w = A * y
3. w_1 = HighBits(w, 2 * gamma_2)
4. c_tilde = H(mu || w_1)
5. c = SampleInBall(c_tilde)
6. z = y + c * s_1
7. If ||z||_infty >= gamma_1 - beta:
       ABORT -> Repeat from step 1
8. r_0 = LowBits(w - c * s_2, 2 * gamma_2)
9. If ||r_0||_infty >= gamma_2 - beta:
       ABORT -> Repeat from step 1
10. h = MakeHint(-c * t_0, w - c * s_2 + c * t_0)
11. Output sig = (c_tilde, z, h) ----------> 1. Check ||z||_infty < gamma_1 - beta
                                             2. c = SampleInBall(c_tilde)
                                             3. w'_1 = UseHint(h, A * z - c * t_1 * 2^d)
                                             4. Accept iff H(mu || w'_1) == c_tilde
```

## 4. Constant-Time & Strict Verification

Rivide's ML-DSA verification engine validates that:
1. The signature size equals exact parameter length (`3309` bytes for ML-DSA-65, `4627` bytes for ML-DSA-87).
2. The number of non-zero hint bits in $\mathbf{h}$ does not exceed the threshold $\omega$.
3. All polynomial operations are calculated in constant time without data-dependent branches.
