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
 * @file dsa_poly.c
 * @brief ML-DSA polynomial arithmetic: addition, subtraction, reduction,
 *        conditional add q, and infinity norm check.
 *
 * Implements polynomial coefficient operations and norm testing routines for ML-DSA.
 */

#include "rivide/internal/dsa_poly.h"

#include "rivide/internal/dsa_reduce.h"
#include "rivide/internal/dsa_sampling.h"

/**
 * @brief Add two polynomials coefficient-wise: r = a + b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void dsa_poly_add(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b) {
    unsigned int i;
    for (i = 0; i < DSA_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * @brief Subtract two polynomials coefficient-wise: r = a - b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void dsa_poly_sub(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b) {
    unsigned int i;
    for (i = 0; i < DSA_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * @brief Reduce all polynomial coefficients modulo q to centered range.
 *
 * @param[in,out] p Polynomial to reduce in-place.
 */
void dsa_poly_reduce(dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < DSA_N; i++) {
        p->coeffs[i] = dsa_reduce32(p->coeffs[i]);
    }
}

/**
 * @brief Add q to negative polynomial coefficients.
 *
 * @param[in,out] p Polynomial to normalize in-place.
 */
void dsa_poly_caddq(dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < DSA_N; i++) {
        p->coeffs[i] = dsa_caddq(p->coeffs[i]);
    }
}

/**
 * @brief Check if the infinity norm of a polynomial exceeds a specified bound.
 *
 * @param[in] p     Polynomial structure to evaluate.
 * @param[in] bound Infinity norm threshold.
 * @return 1 if any coefficient has absolute value >= bound, or 0 otherwise.
 */
int dsa_poly_chknorm(const dsa_poly_t *p, int32_t bound) {
    unsigned int i;
    int32_t t;

    if (bound > (DSA_Q / 2)) {
        return 1;
    }

    for (i = 0; i < DSA_N; i++) {
        t = dsa_reduce32(p->coeffs[i]);
        if (t < 0) {
            t = -t;
        }
        if (t >= bound) {
            return 1;
        }
    }
    return 0;
}
