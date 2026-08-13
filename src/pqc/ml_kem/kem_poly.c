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
 * @file kem_poly.c
 * @brief ML-KEM polynomial arithmetic (add, sub, reduce, tomont, csubq, polyvec ops).
 *
 * Implements coefficient-wise polynomial vector arithmetic and inner products for ML-KEM.
 */

#include "rivide/internal/kem_ntt.h"
#include "rivide/internal/kem_packing.h"
#include "rivide/internal/kem_reduce.h"
#include "rivide/pqc/ntt_simd.h"

/**
 * @brief Add two polynomials coefficient-wise: r = a + b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void poly_add(poly_t *r, const poly_t *a, const poly_t *b) {
    rivide_simd_poly_add_reduce(r->coeffs, a->coeffs, b->coeffs, KEM_Q);
    poly_reduce(r);
}

/**
 * @brief Subtract two polynomials coefficient-wise: r = a - b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void poly_sub(poly_t *r, const poly_t *a, const poly_t *b) {
    rivide_simd_poly_sub_reduce(r->coeffs, a->coeffs, b->coeffs, KEM_Q);
    poly_reduce(r);
}

/**
 * @brief Reduce all polynomial coefficients using Barrett reduction.
 *
 * @param[in,out] p Polynomial to reduce in-place.
 */
void poly_reduce(poly_t *p) {
    unsigned int i;
    for (i = 0; i < KEM_N; i++) {
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
    }
}

/**
 * @brief Multiply all polynomial coefficients by Montgomery factor R.
 *
 * @param[in,out] p Polynomial to scale in-place.
 */
void poly_tomont(poly_t *p) {
    /* 1353 = 2^32 mod 3329 */
    const int16_t f = 1353;
    unsigned int i;
    for (i = 0; i < KEM_N; i++) {
        p->coeffs[i] = montgomery_reduce((int32_t)p->coeffs[i] * f);
    }
}

/**
 * @brief Conditionally subtract q from all polynomial coefficients.
 *
 * @param[in,out] p Polynomial to normalize in-place.
 */
void poly_csubq(poly_t *p) {
    unsigned int i;
    for (i = 0; i < KEM_N; i++) {
        p->coeffs[i] = cond_sub_q(p->coeffs[i]);
    }
}

/**
 * @brief Transform all polynomials in a vector into the NTT domain in-place.
 *
 * @param[in,out] v Polynomial vector to transform.
 * @param[in]     k Module rank.
 */
void polyvec_ntt(polyvec_t *v, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_ntt(&v->vec[i]);
    }
}

/**
 * @brief Pointwise multiplication and accumulation of two polynomial vectors: r = <a, b>.
 *
 * @param[out] r Output accumulated polynomial.
 * @param[in]  a First polynomial vector.
 * @param[in]  b Second polynomial vector.
 * @param[in]  k Module rank.
 */
void polyvec_pointwise_acc(poly_t *r, const polyvec_t *a, const polyvec_t *b, int k) {
    int i;
    poly_t tmp;

    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < k; i++) {
        poly_basemul(&tmp, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &tmp);
    }
    poly_reduce(r);
}
