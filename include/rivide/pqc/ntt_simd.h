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
 * @file ntt_simd.h
 * @brief Portable 8-way SIMD vectorization engine for NTT polynomial transforms.
 *
 * Provides accelerated AVX2 (256-bit) and ARM NEON (128-bit) code paths for
 * Montgomery polynomial addition, subtraction, reduction, and pointwise
 * multiplication in ML-KEM (FIPS 203) and ML-DSA (FIPS 204) algorithms.
 */

#ifndef RIVIDE_NTT_SIMD_H
#define RIVIDE_NTT_SIMD_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/rivide_config.h"

#if defined(RIVIDE_ARCH_X86_64) && (defined(__AVX2__) || defined(RIVIDE_HAS_AVX2))
#include <immintrin.h>
/** @brief Macro flag indicating AVX2 SIMD acceleration is active. */
#define RIVIDE_NTT_AVX2_ENABLED 1
#endif

#if defined(RIVIDE_ARCH_ARM64) && (defined(__ARM_NEON) || defined(RIVIDE_HAS_NEON))
#include <arm_neon.h>
/** @brief Macro flag indicating ARM NEON SIMD acceleration is active. */
#define RIVIDE_NTT_NEON_ENABLED 1
#endif

/**
 * @brief Vectorized 8-way Montgomery reduction and polynomial addition.
 *
 * Computes r[i] = (a[i] + b[i]) mod q for all 256 coefficients of the polynomial.
 * On x86_64 systems with AVX2, processes 16 16-bit coefficients per SIMD vector.
 * On ARM64 systems with NEON, processes 8 16-bit coefficients per SIMD vector.
 * On non-SIMD architectures, falls back to portable ISO C99 logic.
 *
 * @param[out] r  Output coefficient buffer (256 entries).
 * @param[in]  a  First operand coefficient buffer (256 entries).
 * @param[in]  b  Second operand coefficient buffer (256 entries).
 * @param[in]  q  Modulus q (3329 for ML-KEM, 8380417 for ML-DSA).
 */
void rivide_simd_poly_add_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q);

/**
 * @brief Vectorized 8-way polynomial subtraction.
 *
 * Computes r[i] = (a[i] - b[i]) mod q for all 256 coefficients of the polynomial.
 * Uses vector registers without branch instructions or dynamic memory allocation.
 *
 * @param[out] r  Output coefficient buffer (256 entries).
 * @param[in]  a  First operand coefficient buffer (256 entries).
 * @param[in]  b  Second operand coefficient buffer (256 entries).
 * @param[in]  q  Modulus q.
 */
void rivide_simd_poly_sub_reduce(int16_t *r, const int16_t *a, const int16_t *b, int16_t q);

/**
 * @brief Vectorized 8-way pointwise multiplication of NTT polynomials.
 *
 * Computes r[i] = (a[i] * b[i] * R^{-1}) mod q for all 256 coefficients,
 * performing Montgomery multiplication in constant time.
 *
 * @param[out] r     Output polynomial coefficients (256 entries).
 * @param[in]  a     First polynomial coefficients (256 entries).
 * @param[in]  b     Second polynomial coefficients (256 entries).
 * @param[in]  q     Modulus q.
 * @param[in]  qinv  Montgomery q-inverse.
 */
void rivide_simd_poly_pointwise_montgomery(int16_t *r, const int16_t *a, const int16_t *b,
                                           int16_t q, int32_t qinv);

#endif /* RIVIDE_NTT_SIMD_H */
