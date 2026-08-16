<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Number Theoretic Transform (NTT) & Constant-Time Modular Arithmetic

This document details the mathematical theory, butterfly algorithms, and modular reduction techniques implemented in **Rivide**'s high-speed arithmetic core.

## 1. Number Theoretic Transform (NTT) Overview

Polynomial multiplication in the cyclotomic ring $\mathcal{R}_q = \mathbb{Z}_q[X] / (X^{256} + 1)$ naively requires $\mathcal{O}(n^2) = 65,536$ modular multiplications.

The **Number Theoretic Transform (NTT)** computes polynomial multiplication in quasi-linear time $\mathcal{O}(n \log n)$ by transforming polynomials into the frequency domain using primitive roots of unity $\zeta \in \mathbb{Z}_q$:

$$f(X) \cdot g(X) \pmod{X^{256} + 1} = \text{iNTT}(\text{NTT}(f) \circ \text{NTT}(g))$$

## 2. Cooley-Tukey & Gentleman-Sande Butterfly Operations

### Forward NTT (Cooley-Tukey Butterfly)

Transforms coefficient representation into Montgomery-domain NTT representation:

$$\begin{aligned}
a' &= a + b \cdot \zeta \pmod q \\
b' &= a - b \cdot \zeta \pmod q
\end{aligned}$$

### Inverse NTT (Gentleman-Sande Butterfly)

Converts frequency domain representation back to coefficient space:

$$\begin{aligned}
a' &= a + b \pmod q \\
b' &= (a - b) \cdot \zeta^{-1} \pmod q
\end{aligned}$$

## 3. Constant-Time Modular Reductions

### Montgomery Reduction

Let $R = 2^{16}$ (for ML-KEM) or $R = 2^{32}$ (for ML-DSA), where $\gcd(R, q) = 1$.  
The Montgomery reduction algorithm computes $a \cdot R^{-1} \pmod q$ from input $a < q \cdot R$ in constant time using only integer multiplications and bit shifts without hardware division instructions:

```c
int16_t montgomery_reduce(int32_t a) {
    int32_t t = (int32_t)(int16_t)a * QINV;
    t = (a - t * Q) >> 16;
    return (int16_t)t;
}
```

### Barrett Reduction

Computes $a \pmod q$ for arbitrary signed products $a \in [-q \cdot R/2, q \cdot R/2]$ using precomputed multiplier $\mu = \lfloor 2^{26} / q \rceil$:

```c
int16_t barrett_reduce(int16_t a) {
    int32_t t = ((int32_t)a * 20159 + (1 << 25)) >> 26;
    t *= 3329;
    return (int16_t)(a - t);
}
```
