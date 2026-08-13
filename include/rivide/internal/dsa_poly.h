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
 * @file dsa_poly.h
 * @brief Internal ML-DSA polynomial types and shared constants.
 *
 * This header is internal to the Rivide library and should not be
 * included by application code. Use rivide/pqc/ml_dsa.h instead.
 */

#ifndef RIVIDE_INTERNAL_DSA_POLY_H
#define RIVIDE_INTERNAL_DSA_POLY_H

#include <stddef.h>
#include <stdint.h>

/** @brief Polynomial degree. */
#define DSA_N 256

/** @brief Modulus q = 8380417 = 2^23 - 2^13 + 1. */
#define DSA_Q 8380417

/** @brief Montgomery parameter R = 2^32 mod q. */
#define DSA_MONT 4193792

/** @brief q^{-1} mod 2^32 (for Montgomery reduction). */
#define DSA_QINV 58728449

/** @brief Power2Round dropping bits. */
#define DSA_D_BITS 13

/** @brief Maximum module rank k. */
#define DSA_K_MAX 8

/** @brief Maximum l dimension. */
#define DSA_L_MAX 7

/**
 * @brief Polynomial in Z_q[X]/(X^256 + 1) for Dilithium.
 *
 * Coefficients are stored as signed 32-bit integers to accommodate
 * the larger modulus q = 8380417.
 */
typedef struct {
    int32_t coeffs[DSA_N];
} dsa_poly_t;

/**
 * @brief Vector of k polynomials.
 */
typedef struct {
    dsa_poly_t vec[DSA_K_MAX];
} dsa_polyveck_t;

/**
 * @brief Vector of l polynomials.
 */
typedef struct {
    dsa_poly_t vec[DSA_L_MAX];
} dsa_polyvecl_t;

#endif /* RIVIDE_INTERNAL_DSA_POLY_H */
