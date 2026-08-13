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
 * @file kem_ntt.h
 * @brief Internal ML-KEM NTT, INTT, and basemul function declarations.
 *
 * Provides function declarations for forward NTT, inverse NTT, and base
 * polynomial multiplication over Z_q[X]/(X^256 + 1) with q = 3329.
 */

#ifndef RIVIDE_INTERNAL_KEM_NTT_H
#define RIVIDE_INTERNAL_KEM_NTT_H

#include "rivide/internal/kem_poly.h"

/**
 * @brief Precomputed NTT zetas table for q = 3329.
 *
 * Powers of primitive 256th root of unity in Montgomery form.
 */
extern const int16_t zetas[128];

/**
 * @brief In-place forward NTT transform of a polynomial.
 *
 * @param[in,out] p Polynomial to transform into the NTT domain.
 */
void poly_ntt(poly_t *p);

/**
 * @brief In-place inverse NTT transform of a polynomial.
 *
 * @param[in,out] p Polynomial to transform from the NTT domain back to spatial form.
 */
void poly_invntt(poly_t *p);

/**
 * @brief Pointwise base multiplication of two polynomials in the NTT domain.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First input polynomial in NTT domain.
 * @param[in]  b Second input polynomial in NTT domain.
 */
void poly_basemul(poly_t *r, const poly_t *a, const poly_t *b);

#endif /* RIVIDE_INTERNAL_KEM_NTT_H */
