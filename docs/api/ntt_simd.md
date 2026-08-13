# SIMD Acceleration & Feature Query API Reference

Public API routines for querying CPU SIMD vector capabilities and executing vector polynomial arithmetic (`include/rivide/pqc/ntt_simd.h`).

## Header File
```c
#include "rivide/pqc/ntt_simd.h"
```

## Data Types

```c
typedef struct {
    int has_aesni;  /* Intel/AMD AES-NI instructions */
    int has_arm_ce; /* ARMv8 Crypto Extensions */
    int has_avx2;   /* Intel/AMD AVX2 256-bit SIMD */
    int has_neon;   /* ARM NEON 128-bit SIMD */
} rivide_simd_caps_t;
```

## Functions

### `rivide_get_simd_caps`
Queries CPU capabilities and returns feature flags.

```c
rivide_simd_caps_t rivide_get_simd_caps(void);
```

### `poly_add_simd`
Performs element-wise polynomial coefficient addition modulo $q$ using hardware SIMD vector instructions when available.

```c
void poly_add_simd(int16_t r[256], const int16_t a[256], const int16_t b[256]);
```

### `poly_sub_simd`
Performs element-wise polynomial coefficient subtraction modulo $q$ using hardware SIMD vector instructions when available.

```c
void poly_sub_simd(int16_t r[256], const int16_t a[256], const int16_t b[256]);
```
