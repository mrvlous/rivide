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
 * @file kem_poly.h
 * @brief Internal ML-KEM polynomial types and shared constants.
 *
 * This header is internal to the Rivide library and should not be
 * included by application code. Use rivide/pqc/ml_kem.h instead.
 */

#ifndef RIVIDE_INTERNAL_KEM_POLY_H
#define RIVIDE_INTERNAL_KEM_POLY_H

#include <stddef.h>
#include <stdint.h>

/** @brief Polynomial degree. */
#define KEM_N 256

/** @brief Modulus q. */
#define KEM_Q 3329

/** @brief Montgomery parameter: R = 2^16 mod q. */
#define KEM_MONT_R 2285

/** @brief q^{-1} mod 2^16 (used in Montgomery reduction). */
#define KEM_Q_INV 62209

/** @brief Maximum module rank supported. */
#define KEM_K_MAX 4

/**
 * @brief Polynomial in Z_q[X]/(X^256 + 1).
 *
 * Coefficients are stored in the range [0, q-1] for normal form, or in
 * Montgomery form for NTT-domain operations.
 */
typedef struct {
    int16_t coeffs[KEM_N];
} poly_t;

/**
 * @brief Vector of polynomials (one per module dimension).
 */
typedef struct {
    poly_t vec[KEM_K_MAX];
} polyvec_t;

#endif /* RIVIDE_INTERNAL_KEM_POLY_H */
