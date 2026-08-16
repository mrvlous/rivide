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
 * @file kem_encode.h
 * @brief Internal ML-KEM ByteEncode/ByteDecode and message packing declarations.
 *
 * Provides functions for serializing 12-bit polynomial coefficients into bytes,
 * as well as encoding and decoding 32-byte shared messages to/from polynomials.
 */

#ifndef RIVIDE_INTERNAL_KEM_ENCODE_H
#define RIVIDE_INTERNAL_KEM_ENCODE_H

#include <stdint.h>

#include "rivide/internal/kem_poly.h"

/**
 * @brief Serialize a polynomial (12 bits per coefficient) to 384 bytes (ByteEncode_12).
 *
 * @param[out] buf Output byte buffer (384 bytes).
 * @param[in]  p   Polynomial structure to encode.
 */
void poly_tobytes(uint8_t *buf, const poly_t *p);

/**
 * @brief Deserialize a polynomial from 384 bytes (ByteDecode_12).
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer (384 bytes).
 */
void poly_frombytes(poly_t *p, const uint8_t *buf);

/**
 * @brief Encode a 32-byte message into a polynomial (ByteDecode_1).
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  msg Input 32-byte message buffer.
 */
void poly_frommsg(poly_t *p, const uint8_t msg[32]);

/**
 * @brief Decode a polynomial into a 32-byte message (ByteEncode_1).
 *
 * @param[out] msg Output 32-byte message buffer.
 * @param[in]  p   Input polynomial structure.
 */
void poly_tomsg(uint8_t msg[32], const poly_t *p);

/**
 * @brief Serialize a vector of polynomials into byte array (k * 384 bytes).
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  v   Input polynomial vector.
 * @param[in]  k   Module rank.
 */
void polyvec_tobytes(uint8_t *buf, const polyvec_t *v, int k);

/**
 * @brief Deserialize a vector of polynomials from byte array (k * 384 bytes).
 *
 * @param[out] v   Output polynomial vector structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  k   Module rank.
 */
void polyvec_frombytes(polyvec_t *v, const uint8_t *buf, int k);

/**
 * @brief Deserialize a vector of polynomials from byte array with FIPS 203 Section 7.2 Type Check.
 *
 * Verifies that all decoded 12-bit coefficients are strictly less than KEM_Q (3329).
 *
 * @param[out] v   Output polynomial vector structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  k   Module rank.
 * @return 0 on success, or -1 if any coefficient >= 3329.
 */
int polyvec_frombytes_check(polyvec_t *v, const uint8_t *buf, int k);

#endif /* RIVIDE_INTERNAL_KEM_ENCODE_H */
