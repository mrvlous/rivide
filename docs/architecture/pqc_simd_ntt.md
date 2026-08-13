# Hardware SIMD Acceleration Architecture

This document describes Rivide's hardware acceleration abstractions and feature detection capabilities across x86-64 and ARM processors.

## Feature Detection Architecture

Hardware acceleration features are queried at runtime or evaluated at compile time depending on compiler target flags (`src/pqc/ntt_simd.c`):

```c
typedef struct {
    int has_aesni;  /* Intel/AMD AES-NI instructions */
    int has_arm_ce; /* ARMv8 Crypto Extensions */
    int has_avx2;   /* Intel/AMD AVX2 256-bit SIMD */
    int has_neon;   /* ARM NEON 128-bit SIMD */
} rivide_simd_caps_t;
```

## Supported SIMD Acceleration Target Specifications

1. **AVX2 Vectorization (x86-64)**:
   - Uses 256-bit `__m256i` SIMD registers to process 16 16-bit polynomial coefficients in parallel.
   - Accelerates NTT butterfly stages and pointwise polynomial vector additions.

2. **ARM NEON Vectorization (AArch64)**:
   - Uses 128-bit `int16x8_t` SIMD registers for 8-parallel coefficient operations on ARM Cortex processors.

3. **AES-NI & ARM Crypto Extensions**:
   - Accelerates AES single-round encryptions (`_mm_aesenc_si128` / `vaeseq_u8`) for high-throughput symmetric authenticated encryption.
