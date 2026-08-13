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
 * @file dsa_sampling.h
 * @brief Internal ML-DSA polynomial sampling and matrix expansion declarations.
 *
 * Provides declarations for uniform sampling (ExpandA), eta-bounded sampling
 * (ExpandS), gamma1-bounded sampling (ExpandMask), challenge sampling (SampleInBall),
 * and matrix-vector polynomial products.
 */

#ifndef RIVIDE_INTERNAL_DSA_SAMPLING_H
#define RIVIDE_INTERNAL_DSA_SAMPLING_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/internal/dsa_poly.h"

/**
 * @brief Sample a uniformly random polynomial from SHAKE-128 (ExpandA).
 *
 * @param[out] p     Output polynomial with coefficients in [0, q-1].
 * @param[in]  seed  32-byte seed for matrix generation (rho).
 * @param[in]  nonce 16-bit nonce encoding matrix row and column indices.
 */
void dsa_poly_uniform(dsa_poly_t *p, const uint8_t seed[32], uint16_t nonce);

/**
 * @brief Sample a polynomial with coefficients in [-eta, eta] from SHAKE-256 (ExpandS).
 *
 * @param[out] p       Output polynomial structure.
 * @param[in]  seed    Input seed byte array.
 * @param[in]  seedlen Length of seed in bytes.
 * @param[in]  nonce   16-bit nonce counter.
 * @param[in]  eta     Bound parameter (2 or 4).
 */
void dsa_poly_uniform_eta(dsa_poly_t *p, const uint8_t seed[], size_t seedlen, uint16_t nonce,
                          int eta);

/**
 * @brief Sample a masking polynomial with coefficients in [-gamma1+1, gamma1] (ExpandMask).
 *
 * @param[out] p       Output polynomial structure.
 * @param[in]  seed    Input seed byte array.
 * @param[in]  seedlen Length of seed in bytes.
 * @param[in]  nonce   16-bit nonce counter.
 * @param[in]  gamma1  Masking bound (2^17 or 2^19).
 */
void dsa_poly_uniform_gamma1(dsa_poly_t *p, const uint8_t seed[], size_t seedlen, uint16_t nonce,
                             int32_t gamma1);

/**
 * @brief SampleInBall: generate the challenge polynomial c.
 *
 * Produces a polynomial with exactly tau coefficients in {-1, +1}
 * and the remaining coefficients set to zero.
 *
 * @param[out] c    Output challenge polynomial structure.
 * @param[in]  seed Challenge seed byte array (c_tilde).
 * @param[in]  len  Length of seed in bytes.
 * @param[in]  tau  Number of non-zero coefficients.
 */
void dsa_poly_challenge(dsa_poly_t *c, const uint8_t *seed, size_t len, unsigned int tau);

/**
 * @brief Matrix-vector product in NTT domain: t = A * s.
 *
 * @param[out] t   Output polynomial vector (k polynomials).
 * @param[in]  rho 32-byte seed for ExpandA.
 * @param[in]  s   Input polynomial vector (l polynomials, NTT domain).
 * @param[in]  k   Module row dimension.
 * @param[in]  l   Module column dimension.
 */
void dsa_expand_matrix_mul(dsa_polyveck_t *t, const uint8_t rho[32], const dsa_polyvecl_t *s, int k,
                           int l);

/**
 * @brief Check if the infinity norm of a polynomial exceeds a specified bound.
 *
 * @param[in] p     Polynomial structure to evaluate.
 * @param[in] bound Infinity norm threshold.
 * @return 1 if any coefficient has absolute value >= bound, or 0 otherwise.
 */
int dsa_poly_chknorm(const dsa_poly_t *p, int32_t bound);

/**
 * @brief Add two polynomials coefficient-wise: r = a + b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void dsa_poly_add(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b);

/**
 * @brief Subtract two polynomials coefficient-wise: r = a - b.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First operand polynomial.
 * @param[in]  b Second operand polynomial.
 */
void dsa_poly_sub(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b);

/**
 * @brief Reduce all polynomial coefficients modulo q.
 *
 * @param[in,out] p Polynomial to reduce in-place.
 */
void dsa_poly_reduce(dsa_poly_t *p);

/**
 * @brief Add q to negative polynomial coefficients.
 *
 * @param[in,out] p Polynomial to normalize in-place.
 */
void dsa_poly_caddq(dsa_poly_t *p);

#endif /* RIVIDE_INTERNAL_DSA_SAMPLING_H */
