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
 * @file kem_encode.c
 * @brief ML-KEM ByteEncode/ByteDecode and message encoding/decoding implementation.
 *
 * Implements ByteEncode_12 and ByteDecode_12 serialization routines for 12-bit
 * polynomial coefficients as well as 32-byte message encoding specified in FIPS 203.
 */

#include "rivide/internal/kem_encode.h"

#include "rivide/internal/kem_compress.h"

/**
 * @brief Serialize a polynomial (12 bits per coefficient) to 384 bytes (ByteEncode_12).
 *
 * @param[out] buf Output byte buffer (384 bytes).
 * @param[in]  p   Polynomial structure to encode.
 */
void poly_tobytes(uint8_t *buf, const poly_t *p) {
    unsigned int i;
    for (i = 0; i < KEM_N / 2; i++) {
        uint16_t t0 = (uint16_t)((uint16_t)p->coeffs[2 * i] & 0x0FFF);
        uint16_t t1 = (uint16_t)((uint16_t)p->coeffs[2 * i + 1] & 0x0FFF);
        buf[3 * i] = (uint8_t)(t0 & 0xFF);
        buf[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 & 0x0F) << 4));
        buf[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

/**
 * @brief Deserialize a polynomial from 384 bytes (ByteDecode_12).
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer (384 bytes).
 */
void poly_frombytes(poly_t *p, const uint8_t *buf) {
    unsigned int i;
    for (i = 0; i < KEM_N / 2; i++) {
        p->coeffs[2 * i] =
            (int16_t)(((uint16_t)buf[3 * i] | ((uint16_t)buf[3 * i + 1] << 8)) & 0x0FFF);
        p->coeffs[2 * i + 1] =
            (int16_t)((((uint16_t)buf[3 * i + 1] >> 4) | ((uint16_t)buf[3 * i + 2] << 4)) & 0x0FFF);
    }
}

/**
 * @brief Encode a 32-byte message into a polynomial (ByteDecode_1).
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  msg Input 32-byte message buffer.
 */
void poly_frommsg(poly_t *p, const uint8_t msg[32]) {
    unsigned int i, j;
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 8; j++) {
            p->coeffs[8 * i + j] = decompress_coeff((uint16_t)((msg[i] >> j) & 1), 1);
        }
    }
}

/**
 * @brief Decode a polynomial into a 32-byte message (ByteEncode_1).
 *
 * @param[out] msg Output 32-byte message buffer.
 * @param[in]  p   Input polynomial structure.
 */
void poly_tomsg(uint8_t msg[32], const poly_t *p) {
    unsigned int i, j;
    for (i = 0; i < 32; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            uint16_t t = compress_coeff(p->coeffs[8 * i + j], 1);
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

/**
 * @brief Serialize a vector of polynomials into byte array (k * 384 bytes).
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  v   Input polynomial vector.
 * @param[in]  k   Module rank.
 */
void polyvec_tobytes(uint8_t *buf, const polyvec_t *v, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_tobytes(buf + 384 * i, &v->vec[i]);
    }
}

/**
 * @brief Deserialize a vector of polynomials from byte array (k * 384 bytes).
 *
 * @param[out] v   Output polynomial vector structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  k   Module rank.
 */
void polyvec_frombytes(polyvec_t *v, const uint8_t *buf, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_frombytes(&v->vec[i], buf + 384 * i);
    }
}
