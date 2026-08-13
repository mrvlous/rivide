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
 * @file dsa_ntt.h
 * @brief Internal ML-DSA Number Theoretic Transform (NTT) declarations.
 *
 * Provides function declarations for forward NTT, inverse NTT, and pointwise
 * polynomial multiplication over Z_q[X]/(X^256 + 1) with q = 8380417.
 */

#ifndef RIVIDE_INTERNAL_DSA_NTT_H
#define RIVIDE_INTERNAL_DSA_NTT_H

#include "rivide/internal/dsa_poly.h"

/**
 * @brief NTT zeta table for q = 8380417.
 *
 * Precomputed roots of unity in Montgomery form, in bit-reversed order
 * for the iterative NTT butterfly. The primitive 512th root of unity
 * modulo q is zeta = 1753.
 */
extern const int32_t dsa_zetas[DSA_N];

/**
 * @brief In-place forward NTT for Dilithium polynomials.
 *
 * @param[in,out] p Polynomial to transform into the NTT domain.
 */
void dsa_poly_ntt(dsa_poly_t *p);

/**
 * @brief In-place inverse NTT for Dilithium polynomials.
 *
 * @param[in,out] p Polynomial to transform from the NTT domain back to spatial form.
 */
void dsa_poly_invntt(dsa_poly_t *p);

/**
 * @brief Pointwise multiplication of two polynomials in the NTT domain.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First input polynomial in NTT domain.
 * @param[in]  b Second input polynomial in NTT domain.
 */
void dsa_poly_pointwise(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b);

/**
 * @brief Multiply polynomial coefficients by R mod q to convert to Montgomery domain.
 *
 * @param[in,out] p Polynomial to convert in-place.
 */
void dsa_poly_tomont(dsa_poly_t *p);

#endif /* RIVIDE_INTERNAL_DSA_NTT_H */
