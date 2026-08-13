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
 * @file kem_compress.h
 * @brief Internal ML-KEM coefficient, polynomial, and polyvec compression/decompression.
 *
 * Provides lossy compression functions for ciphertext components (u, v) and
 * key structures according to NIST FIPS 203 specifications.
 */

#ifndef RIVIDE_INTERNAL_KEM_COMPRESS_H
#define RIVIDE_INTERNAL_KEM_COMPRESS_H

#include <stdint.h>

#include "rivide/internal/kem_poly.h"

/**
 * @brief Compress a single coefficient from Z_q to d bits.
 *
 * Computes round(2^d / q * x) mod 2^d.
 *
 * @param[in] x Coefficient in [0, q-1].
 * @param[in] d Target bit length.
 * @return Compressed d-bit integer value.
 */
uint16_t compress_coeff(int16_t x, int d);

/**
 * @brief Decompress a d-bit integer back to a coefficient in Z_q.
 *
 * Computes round(q / 2^d * x).
 *
 * @param[in] x Compressed d-bit integer.
 * @param[in] d Original bit length.
 * @return Decompressed coefficient in [0, q-1].
 */
int16_t decompress_coeff(uint16_t x, int d);

/**
 * @brief Compress all coefficients of a polynomial into a byte array.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  p   Input polynomial structure.
 * @param[in]  d   Target bit length per coefficient (d in {1, 4, 5, 10, 11}).
 */
void poly_compress(uint8_t *buf, const poly_t *p, int d);

/**
 * @brief Decompress coefficients of a polynomial from a byte array.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  d   Bit length per compressed coefficient.
 */
void poly_decompress(poly_t *p, const uint8_t *buf, int d);

/**
 * @brief Compress a vector of polynomials into a byte array.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  v   Input polynomial vector.
 * @param[in]  k   Module rank.
 * @param[in]  d   Target bit length per coefficient (10 or 11).
 */
void polyvec_compress(uint8_t *buf, const polyvec_t *v, int k, int d);

/**
 * @brief Decompress a vector of polynomials from a byte array.
 *
 * @param[out] v   Output polynomial vector structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  k   Module rank.
 * @param[in]  d   Bit length per compressed coefficient (10 or 11).
 */
void polyvec_decompress(polyvec_t *v, const uint8_t *buf, int k, int d);

#endif /* RIVIDE_INTERNAL_KEM_COMPRESS_H */
