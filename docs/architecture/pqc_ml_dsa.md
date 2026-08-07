# ML-DSA Digital Signature Algorithm (NIST FIPS 204)

This document describes the design, algebraic structures, and implementation details of the **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) implemented in [`src/pqc/ml_dsa.c`](../../src/pqc/ml_dsa.c).

---

## 1. Overview

ML-DSA (standardized in NIST FIPS 204, based on the Dilithium submission) provides EUF-CMA (Existential Unforgeability under Chosen Message Attacks) secure digital signatures. The security relies on the hardness of the Module Short Integer Solution (**MSIS**) and Module Learning With Errors (**MLWE**) problems.

Rivide implements two standard parameter sets:
*   **ML-DSA-65**: NIST Security Category 3 (Matrix dimension $6 \times 5$).
*   **ML-DSA-87**: NIST Security Category 5 (Matrix dimension $8 \times 7$).

---

## 2. Mathematical Parameters & Ring Definition

ML-DSA operates over polynomials in the ring:
$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$
where:
*   Polynomial degree $n = 256$.
*   Prime modulus $q = 8380417 = 2^{23} - 2^{13} + 1$.
*   Primitive 512th root of unity $\zeta = 1753 \pmod q$.

### Parameter Set Specification

| Parameter | ML-DSA-65 | ML-DSA-87 | Description |
| :--- | :--- | :--- | :--- |
| **Matrix Size ($k \times l$)** | $6 \times 5$ | $8 \times 7$ | Dimensions of public matrix $\mathbf{A}$ |
| **Public Key Size** | `1952` bytes | `2592` bytes | Packed public key ($t_1 \parallel \rho$) |
| **Secret Key Size** | `4032` bytes | `4896` bytes | Secret key vector components ($\rho \parallel K \parallel tr \parallel s_1 \parallel s_2 \parallel t_0$) |
| **Signature Size** | `3309` bytes | `4627` bytes | Digital signature ($\tilde{c} \parallel z \parallel h$) |
| **Secret Bound ($\eta$)** | `4` | `2` | Bound for secret vectors $s_1, s_2$ |
| **Gamma1 ($\gamma_1$)** | $2^{19}$ | $2^{19}$ | Masking vector coefficient bound |
| **Gamma2 ($\gamma_2$)** | $(q-1)/32$ | $(q-1)/32$ | High-bits decomposition parameter |
| **Challenge Tau ($\tau$)** | `49` | `60` | Number of $\pm 1$ coefficients in challenge $c$ |
| **Omega ($\omega$)** | `55` | `75` | Maximum number of non-zero hints |

---

## 3. Key Algorithmic Components

### Rounding & Decomposition Functions
To shorten public keys and signatures, ML-DSA uses exact high/low coefficient decomposition:
*   **`Power2Round`**: Splits polynomial $t$ into $(t_1, t_0)$ such that $t = t_1 \cdot 2^d + t_0$, where $d = 13$.
*   **`Decompose`**: Splits coefficient $a$ into high part $a_1$ and low part $a_0$ modulo $2\gamma_2$.
*   **`MakeHint` / `UseHint`**: Generates and applies 1-bit hints $h$ allowing the verifier to recover high bits $w_1$ despite small perturbation from $c \cdot t_0$.

### Rejection Sampling Signature Loop
Signing uses the Fiat-Shamir with Abort framework:
1. Sample masking vector $\mathbf{y}$ from $[-\gamma_1+1, \gamma_1]$ using SHAKE-256 (ExpandMask).
2. Compute $\mathbf{w} = \mathbf{A} \cdot \mathrm{NTT}(\mathbf{y})$ and decompose into high bits $\mathbf{w}_1$.
3. Compute challenge hash $\tilde{c} = \mathrm{CRH}(\mu \parallel \mathbf{w}_1)$.
4. Sample challenge polynomial $c = \mathrm{SampleInBall}(\tilde{c})$.
5. Compute candidate signature vector $\mathbf{z} = \mathbf{y} + c \cdot \mathbf{s}_1$.
6. **Rejection Test**:
    *   If $\|\mathbf{z}\|_\infty \ge \gamma_1 - \beta$, abort and retry.
    *   If $\|\mathrm{LowBits}(\mathbf{w} - c\cdot\mathbf{s}_2)\|_\infty \ge \gamma_2 - \beta$, abort and retry.
    *   If hint count exceeds $\omega$, abort and retry.
7. Output valid signature $(\tilde{c}, \mathbf{z}, h)$.
