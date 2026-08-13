# ML-DSA Architecture Specification (NIST FIPS 204)

This document details the internal architecture, mathematical principles, and module structure of the **ML-DSA Digital Signature Algorithm** (Dilithium) in Rivide.

## Mathematical Foundation

ML-DSA is based on the hardness of the Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems over the polynomial ring $R_q = \mathbb{Z}_q[X] / (X^N + 1)$:
- $N = 256$ (degree of polynomials).
- $q = 8380417 = 2^{23} - 2^{13} + 1$ (prime modulus).
- $\gamma_1, \gamma_2, \tau, \beta$ (parameterized bounds).

```
          Seed Matrix A (k x l) * Secret Vector s1 (l) -> Public Vector t
                                       |
                             +---------v---------+
                             | Rejection Sample  |
                             | Sign (y, z, h)    |
                             +---------+---------+
                                       |
                             +---------v---------+
                             | Pack & Verify     |
                             +-------------------+
```

## Security Parameter Sets

Rivide implements ML-DSA-65 and ML-DSA-87 as specified in FIPS 204:

| Parameter | ML-DSA-65 | ML-DSA-87 |
| :--- | :--- | :--- |
| **NIST Security Category** | Category 3 (AES-192 equivalent) | Category 5 (AES-256 equivalent) |
| **Matrix Dimensions ($k, l$)** | (6, 5) | (8, 7) |
| **Secret Bound ($\eta$)** | 4 | 2 |
| **Gamma1 ($\gamma_1$)** | $2^{17} = 131072$ | $2^{19} = 524288$ |
| **Gamma2 ($\gamma_2$)** | $(q-1)/88 = 95232$ | $(q-1)/32 = 261888$ |
| **Public Key Size** | 1952 bytes | 2592 bytes |
| **Secret Key Size** | 4032 bytes | 4896 bytes |
| **Signature Size** | 3309 bytes | 4627 bytes |

## Internal Modular Subsystems

The ML-DSA engine is structured into modular units in `src/pqc/ml_dsa/`:

1. **`dsa_reduce.c`**: Montgomery and Barrett modular reduction modulo $q = 8380417$.
2. **`dsa_ntt.c`**: 256-point NTT, inverse NTT, and pointwise vector multiplication.
3. **`dsa_poly.c`**: Polynomial addition, subtraction, shift, and norm checks ($\|p\|_{\infty}$).
4. **`dsa_rounding.c`**: HighBits, LowBits, Decompose, and MakeHint/UseHint algorithms.
5. **`dsa_sampling.c`**: Rejection sampling from SHAKE-256 streams for matrix $A$, mask vectors $y$, and sample in $\text{Ball}(\tau)$.
6. **`dsa_packing.c`**: Bit-packing and unpacking routines for keys, signatures, and hint vectors.
7. **`ml_dsa.c`**: Public API orchestration for KeyGen, Sign, and Verify.
