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
 * @file kem_packing.h
 * @brief Internal ML-KEM polynomial operations and polyvec arithmetic.
 *
 * Provides functions for coefficient-wise addition, subtraction, reduction,
 * Montgomery conversion, as well as polyvec NTT and inner products.
 */

#ifndef RIVIDE_INTERNAL_KEM_PACKING_H
#define RIVIDE_INTERNAL_KEM_PACKING_H

#include "rivide/internal/kem_poly.h"

/**
 * @brief Add two polynomials coefficient-wise: r = a + b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void poly_add(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Subtract two polynomials coefficient-wise: r = a - b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void poly_sub(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Reduce all polynomial coefficients using Barrett reduction.
 *
 * @param[in,out] p Polynomial to reduce in-place.
 */
void poly_reduce(poly_t *p);

/**
 * @brief Multiply all polynomial coefficients by Montgomery factor R.
 *
 * @param[in,out] p Polynomial to scale in-place.
 */
void poly_tomont(poly_t *p);

/**
 * @brief Conditionally subtract q from all polynomial coefficients.
 *
 * @param[in,out] p Polynomial to normalize in-place.
 */
void poly_csubq(poly_t *p);

/**
 * @brief Transform all polynomials in a vector into the NTT domain in-place.
 *
 * @param[in,out] v Polynomial vector to transform.
 * @param[in]     k Module rank.
 */
void polyvec_ntt(polyvec_t *v, int k);

/**
 * @brief Pointwise multiplication and accumulation of two polynomial vectors: r = <a, b>.
 *
 * @param[out] r Output accumulated polynomial.
 * @param[in]  a First polynomial vector.
 * @param[in]  b Second polynomial vector.
 * @param[in]  k Module rank.
 */
void polyvec_pointwise_acc(poly_t *r, const polyvec_t *a, const polyvec_t *b, int k);

#endif /* RIVIDE_INTERNAL_KEM_PACKING_H */
