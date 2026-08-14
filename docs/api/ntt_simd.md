# SIMD Acceleration & Feature Query API Reference

Public API routines for querying CPU SIMD vector capabilities and executing vector polynomial arithmetic (`include/rivide/pqc/ntt_simd.h`, `include/rivide/rivide_config.h`).

## Header Files
```c
#include "rivide/pqc/ntt_simd.h"
#include "rivide/rivide_config.h"
```

## Hardware Feature Query Functions

Rivide dynamically inspects hardware features at runtime:

```c
int rivide_has_aesni(void);      /* Intel/AMD AES-NI instructions */
int rivide_has_arm_crypto(void); /* ARMv8 Cryptography Extensions */
int rivide_has_avx2(void);       /* Intel/AMD AVX2 256-bit SIMD */
int rivide_has_neon(void);       /* ARM NEON 128-bit SIMD */
```
- **Returns**: `1` if the hardware acceleration capability is supported and detected, `0` otherwise.

---

## Vectorized Polynomial Arithmetic

### `rivide_simd_poly_add_reduce`
Computes element-wise polynomial coefficient addition modulo $q$ ($r[i] = (a[i] + b[i]) \pmod q$) for all 256 coefficients using AVX2 or NEON vectorization when available.

```c
void rivide_simd_poly_add_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q);
```
- **`r`**: Output coefficient buffer (256 entries).
- **`a`**: First operand coefficient buffer (256 entries).
- **`b`**: Second operand coefficient buffer (256 entries).
- **`q`**: Modulus $q$ (e.g., 3329 for ML-KEM).

### `rivide_simd_poly_sub_reduce`
Computes element-wise polynomial coefficient subtraction modulo $q$ ($r[i] = (a[i] - b[i]) \pmod q$) for all 256 coefficients using vector registers.

```c
void rivide_simd_poly_sub_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q);
```
- **`r`**: Output coefficient buffer (256 entries).
- **`a`**: First operand coefficient buffer (256 entries).
- **`b`**: Second operand coefficient buffer (256 entries).
- **`q`**: Modulus $q$.

### `rivide_simd_poly_pointwise_montgomery`
Computes vectorized 8-way pointwise multiplication of NTT polynomials ($r[i] = (a[i] \cdot b[i] \cdot R^{-1}) \pmod q$) in constant time.

```c
void rivide_simd_poly_pointwise_montgomery(int16_t *r, const int16_t *a, const int16_t *b,
                                           int16_t q, int32_t qinv);
```
- **`r`**: Output coefficient buffer (256 entries).
- **`a`**: First polynomial coefficient buffer (256 entries).
- **`b`**: Second polynomial coefficient buffer (256 entries).
- **`q`**: Modulus $q$.
- **`qinv`**: Montgomery $q$-inverse constant.
