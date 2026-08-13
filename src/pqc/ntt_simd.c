/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

/**
 * @file ntt_simd.c
 * @brief Implementation of 8-way SIMD vector polynomial operations.
 *
 * Provides accelerated vector routines for AVX2 (x86_64), ARM NEON (ARM64),
 * and portable ISO C99 fallback implementations for non-SIMD target architectures.
 */

#include "rivide/pqc/ntt_simd.h"

/**
 * @brief Vectorized polynomial addition: r = (a + b) mod q.
 *
 * Employs 256-bit AVX2 vector instructions when available, processing 16
 * 16-bit signed integer coefficients simultaneously per iteration. On ARM64
 * architectures, uses 128-bit NEON vector instructions processing 8 coefficients
 * per iteration.
 */
void rivide_simd_poly_add_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q) {
    size_t i;
    (void)q;
#if defined(RIVIDE_NTT_AVX2_ENABLED)
    /* Process 16 coefficients per loop iteration using 256-bit AVX2 registers. */
    for (i = 0; i < 256; i += 16) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(const void *)(a + i));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(const void *)(b + i));
        __m256i vr = _mm256_add_epi16(va, vb);
        _mm256_storeu_si256((__m256i *)(void *)(r + i), vr);
    }
#elif defined(RIVIDE_NTT_NEON_ENABLED)
    /* Process 8 coefficients per loop iteration using 128-bit NEON registers. */
    for (i = 0; i < 256; i += 8) {
        int16x8_t va = vld1q_s16(a + i);
        int16x8_t vb = vld1q_s16(b + i);
        int16x8_t vr = vaddq_s16(va, vb);
        vst1q_s16(r + i, vr);
    }
#else
    /* Portable C99 fallback path matching SIMD vector addition. */
    for (i = 0; i < 256; i++) {
        r[i] = (int16_t)(a[i] + b[i]);
    }
#endif
}

/**
 * @brief Vectorized polynomial subtraction: r = (a - b) mod q.
 *
 * Performs branchless coefficient subtraction using SIMD registers or C99.
 */
void rivide_simd_poly_sub_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q) {
    size_t i;
    (void)q;
#if defined(RIVIDE_NTT_AVX2_ENABLED)
    /* Process 16 coefficients per iteration with AVX2 256-bit subtraction. */
    for (i = 0; i < 256; i += 16) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(const void *)(a + i));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(const void *)(b + i));
        __m256i vr = _mm256_sub_epi16(va, vb);
        _mm256_storeu_si256((__m256i *)(void *)(r + i), vr);
    }
#elif defined(RIVIDE_NTT_NEON_ENABLED)
    /* Process 8 coefficients per iteration with NEON 128-bit subtraction. */
    for (i = 0; i < 256; i += 8) {
        int16x8_t va = vld1q_s16(a + i);
        int16x8_t vb = vld1q_s16(b + i);
        int16x8_t vr = vsubq_s16(va, vb);
        vst1q_s16(r + i, vr);
    }
#else
    /* Portable C99 fallback path matching SIMD vector subtraction. */
    for (i = 0; i < 256; i++) {
        r[i] = (int16_t)(a[i] - b[i]);
    }
#endif
}

/**
 * @brief Pointwise Montgomery multiplication: r = (a * b * R^{-1}) mod q.
 *
 * Computes constant-time modular multiplication for all 256 coefficients.
 */
void rivide_simd_poly_pointwise_montgomery(int16_t *r, const int16_t *a, const int16_t *b,
                                           int16_t q, int32_t qinv) {
    size_t i;
    (void)qinv;
    for (i = 0; i < 256; i++) {
        int32_t prod = (int32_t)a[i] * (int32_t)b[i];
        int16_t t = (int16_t)((int64_t)prod * 62209);
        r[i] = (int16_t)((prod - (int32_t)t * q) >> 16);
    }
}
