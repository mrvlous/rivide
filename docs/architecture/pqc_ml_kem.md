# ML-KEM Architecture Specification (NIST FIPS 203)

This document details the internal architecture, mathematical formulations, and modular design of the **ML-KEM Key Encapsulation Mechanism** in Rivide.

## Mathematical Foundation

ML-KEM operates over the module polynomial ring $R_q = \mathbb{Z}_q[X] / (X^N + 1)$ with parameters:
- $N = 256$ (degree of polynomials).
- $q = 3329$ (prime modulus).
- $\zeta = 17$ (primitive 256-th root of unity modulo $q$).

```
       Polynomial Vector A (k x k) * Vector s (k) + Error e (k)
                             |
                   +---------v---------+
                   | Number Theoretic  |
                   | Transform (NTT)   |
                   +---------+---------+
                             |
                   +---------v---------+
                   |  Compress & Pack  |
                   +-------------------+
```

## Security Parameter Sets

Rivide supports the two primary security parameter sets defined in FIPS 203:

| Parameter | ML-KEM-768 | ML-KEM-1024 |
| :--- | :--- | :--- |
| **NIST Security Category** | Category 3 (AES-192 equivalent) | Category 5 (AES-256 equivalent) |
| **Module Rank ($k$)** | 3 | 4 |
| **Noise Parameter ($\eta_1$)** | 2 | 2 |
| **Noise Parameter ($\eta_2$)** | 2 | 2 |
| **Ciphertext Compression ($d_u, d_v$)** | (10, 4) | (11, 5) |
| **Public Key Size** | 1184 bytes | 1568 bytes |
| **Secret Key Size** | 2400 bytes | 3168 bytes |
| **Ciphertext Size** | 1088 bytes | 1568 bytes |
| **Shared Key Size** | 32 bytes | 32 bytes |

## Internal Modular Subsystems

The ML-KEM engine is split into single-responsibility C modules inside `src/pqc/ml_kem/`:

1. **`kem_reduce.c`**: Barrett and Montgomery reduction modulo $q = 3329$.
2. **`kem_ntt.c`**: In-place forward NTT, inverse NTT (`poly_invntt`), and pointwise base multiplication (`poly_basemul`).
3. **`kem_poly.c`**: Polynomial addition, subtraction, reduction, and scalar transformations.
4. **`kem_cbd.c`**: Centered Binomial Distribution sampling for noise polynomials ($\text{CBD}_{\eta}$).
5. **`kem_compress.c`**: Lossy coefficient compression and decompression ($d \in \{1, 4, 5, 10, 11\}$).
6. **`kem_encode.c`**: Message polynomial encoding and decoding.
7. **`kem_sampling.c`**: Uniform matrix sampling from seed using SHAKE-128 rejection sampling.
8. **`ml_kem.c`**: Public API orchestration for KeyGen, Encapsulation, and Decapsulation.

## Fujisaki-Okamoto Transform & Implicit Rejection

Decapsulation implements the post-quantum Fujisaki-Okamoto (FO) transform with implicit rejection:
1. Decrypt ciphertext to candidate message $m'$.
2. Re-encrypt $m'$ to candidate ciphertext $c'$.
3. Compare $c$ and $c'$ in constant time using `rivide_ct_memcmp`.
4. Select the true shared key or pseudo-random rejection key $K_{\text{reject}} = \text{SHAKE256}(z \parallel c)$ in constant time using `rivide_ct_select`.
