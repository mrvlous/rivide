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
 * @file kem_compress.c
 * @brief ML-KEM coefficient, polynomial, and polyvec compression/decompression logic.
 *
 * Implements standard lossy coefficient compression Compress_d and Decompress_d
 * for bit lengths d in {1, 4, 5, 10, 11} specified in NIST FIPS 203.
 */

#include "rivide/internal/kem_compress.h"

#include "rivide/internal/kem_reduce.h"

/**
 * @brief Compress a single coefficient from Z_q to d bits.
 *
 * Computes round(2^d / q * x) mod 2^d.
 *
 * @param[in] x Coefficient in [0, q-1].
 * @param[in] d Target bit length.
 * @return Compressed d-bit integer value.
 */
uint16_t compress_coeff(int16_t x, int d) {
    int16_t c = barrett_reduce(x);
    c = cond_sub_q(c);
    c = (int16_t)(c + ((c >> 15) & KEM_Q));
    uint32_t t = (uint32_t)(uint16_t)c;
    t = (t << d) + KEM_Q / 2;
    t = t / KEM_Q;
    return (uint16_t)(t & ((1u << d) - 1));
}

/**
 * @brief Decompress a d-bit integer back to a coefficient in Z_q.
 *
 * Computes round(q / 2^d * x).
 *
 * @param[in] x Compressed d-bit integer.
 * @param[in] d Original bit length.
 * @return Decompressed coefficient in [0, q-1].
 */
int16_t decompress_coeff(uint16_t x, int d) {
    uint32_t t = ((uint32_t)x * KEM_Q + (1u << (d - 1))) >> d;
    return (int16_t)t;
}

/**
 * @brief Compress all coefficients of a polynomial into a byte array.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  p   Input polynomial structure.
 * @param[in]  d   Target bit length per coefficient (d in {1, 4, 5, 10, 11}).
 */
void poly_compress(uint8_t *buf, const poly_t *p, int d) {
    unsigned int i, j;

    if (d == 4) {
        for (i = 0; i < KEM_N / 2; i++) {
            uint8_t t0 = (uint8_t)compress_coeff(p->coeffs[2 * i], d);
            uint8_t t1 = (uint8_t)compress_coeff(p->coeffs[2 * i + 1], d);
            buf[i] = (uint8_t)(t0 | (t1 << 4));
        }
    } else if (d == 5) {
        for (i = 0; i < KEM_N / 8; i++) {
            uint8_t t[8];
            for (j = 0; j < 8; j++) {
                t[j] = (uint8_t)compress_coeff(p->coeffs[8 * i + j], d);
            }
            buf[5 * i] = (uint8_t)(t[0] | (t[1] << 5));
            buf[5 * i + 1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            buf[5 * i + 2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
            buf[5 * i + 3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            buf[5 * i + 4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
        }
    } else if (d == 10) {
        for (i = 0; i < KEM_N / 4; i++) {
            uint16_t t[4];
            for (j = 0; j < 4; j++) {
                t[j] = compress_coeff(p->coeffs[4 * i + j], d);
            }
            buf[5 * i] = (uint8_t)(t[0] & 0xFF);
            buf[5 * i + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x3F) << 2));
            buf[5 * i + 2] = (uint8_t)((t[1] >> 6) | ((t[2] & 0x0F) << 4));
            buf[5 * i + 3] = (uint8_t)((t[2] >> 4) | ((t[3] & 0x03) << 6));
            buf[5 * i + 4] = (uint8_t)(t[3] >> 2);
        }
    } else if (d == 11) {
        for (i = 0; i < KEM_N / 8; i++) {
            uint16_t t[8];
            for (j = 0; j < 8; j++) {
                t[j] = compress_coeff(p->coeffs[8 * i + j], d);
            }
            buf[11 * i] = (uint8_t)(t[0] & 0xFF);
            buf[11 * i + 1] = (uint8_t)((t[0] >> 8) | ((t[1] & 0x1F) << 3));
            buf[11 * i + 2] = (uint8_t)((t[1] >> 5) | ((t[2] & 0x03) << 6));
            buf[11 * i + 3] = (uint8_t)((t[2] >> 2) & 0xFF);
            buf[11 * i + 4] = (uint8_t)((t[2] >> 10) | ((t[3] & 0x7F) << 1));
            buf[11 * i + 5] = (uint8_t)((t[3] >> 7) | ((t[4] & 0x0F) << 4));
            buf[11 * i + 6] = (uint8_t)((t[4] >> 4) | ((t[5] & 0x01) << 7));
            buf[11 * i + 7] = (uint8_t)((t[5] >> 1) & 0xFF);
            buf[11 * i + 8] = (uint8_t)((t[5] >> 9) | ((t[6] & 0x3F) << 2));
            buf[11 * i + 9] = (uint8_t)((t[6] >> 6) | ((t[7] & 0x07) << 5));
            buf[11 * i + 10] = (uint8_t)(t[7] >> 3);
        }
    }
}

/**
 * @brief Decompress coefficients of a polynomial from a byte array.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  d   Bit length per compressed coefficient.
 */
void poly_decompress(poly_t *p, const uint8_t *buf, int d) {
    unsigned int i, j;

    if (d == 4) {
        for (i = 0; i < KEM_N / 2; i++) {
            p->coeffs[2 * i] = decompress_coeff((uint16_t)(buf[i] & 0x0F), d);
            p->coeffs[2 * i + 1] = decompress_coeff((uint16_t)(buf[i] >> 4), d);
        }
    } else if (d == 5) {
        for (i = 0; i < KEM_N / 8; i++) {
            uint8_t t[8];
            t[0] = (uint8_t)(buf[5 * i] & 0x1F);
            t[1] = (uint8_t)((buf[5 * i] >> 5) | ((buf[5 * i + 1] & 0x03) << 3));
            t[2] = (uint8_t)((buf[5 * i + 1] >> 2) & 0x1F);
            t[3] = (uint8_t)((buf[5 * i + 1] >> 7) | ((buf[5 * i + 2] & 0x0F) << 1));
            t[4] = (uint8_t)((buf[5 * i + 2] >> 4) | ((buf[5 * i + 3] & 0x01) << 4));
            t[5] = (uint8_t)((buf[5 * i + 3] >> 1) & 0x1F);
            t[6] = (uint8_t)((buf[5 * i + 3] >> 6) | ((buf[5 * i + 4] & 0x07) << 2));
            t[7] = (uint8_t)((buf[5 * i + 4] >> 3) & 0x1F);
            for (j = 0; j < 8; j++) {
                p->coeffs[8 * i + j] = decompress_coeff((uint16_t)t[j], d);
            }
        }
    } else if (d == 10) {
        for (i = 0; i < KEM_N / 4; i++) {
            uint16_t t[4];
            t[0] = (uint16_t)(((uint16_t)buf[5 * i] | ((uint16_t)buf[5 * i + 1] << 8)) & 0x3FF);
            t[1] = (uint16_t)((((uint16_t)buf[5 * i + 1] >> 2) | ((uint16_t)buf[5 * i + 2] << 6)) &
                              0x3FF);
            t[2] = (uint16_t)((((uint16_t)buf[5 * i + 2] >> 4) | ((uint16_t)buf[5 * i + 3] << 4)) &
                              0x3FF);
            t[3] = (uint16_t)((((uint16_t)buf[5 * i + 3] >> 6) | ((uint16_t)buf[5 * i + 4] << 2)) &
                              0x3FF);
            for (j = 0; j < 4; j++) {
                p->coeffs[4 * i + j] = decompress_coeff(t[j], d);
            }
        }
    } else if (d == 11) {
        for (i = 0; i < KEM_N / 8; i++) {
            uint16_t t[8];
            t[0] = (uint16_t)(((uint16_t)buf[11 * i] | ((uint16_t)buf[11 * i + 1] << 8)) & 0x7FF);
            t[1] =
                (uint16_t)((((uint16_t)buf[11 * i + 1] >> 3) | ((uint16_t)buf[11 * i + 2] << 5)) &
                           0x7FF);
            t[2] = (uint16_t)((((uint16_t)buf[11 * i + 2] >> 6) | ((uint16_t)buf[11 * i + 3] << 2) |
                               ((uint16_t)buf[11 * i + 4] << 10)) &
                              0x7FF);
            t[3] =
                (uint16_t)((((uint16_t)buf[11 * i + 4] >> 1) | ((uint16_t)buf[11 * i + 5] << 7)) &
                           0x7FF);
            t[4] =
                (uint16_t)((((uint16_t)buf[11 * i + 5] >> 4) | ((uint16_t)buf[11 * i + 6] << 4)) &
                           0x7FF);
            t[5] = (uint16_t)((((uint16_t)buf[11 * i + 6] >> 7) | ((uint16_t)buf[11 * i + 7] << 1) |
                               ((uint16_t)buf[11 * i + 8] << 9)) &
                              0x7FF);
            t[6] =
                (uint16_t)((((uint16_t)buf[11 * i + 8] >> 2) | ((uint16_t)buf[11 * i + 9] << 6)) &
                           0x7FF);
            t[7] =
                (uint16_t)((((uint16_t)buf[11 * i + 9] >> 5) | ((uint16_t)buf[11 * i + 10] << 3)) &
                           0x7FF);
            for (j = 0; j < 8; j++) {
                p->coeffs[8 * i + j] = decompress_coeff(t[j], d);
            }
        }
    }
}

/**
 * @brief Compress a vector of polynomials into a byte array.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  v   Input polynomial vector.
 * @param[in]  k   Module rank.
 * @param[in]  d   Target bit length per coefficient (10 or 11).
 */
void polyvec_compress(uint8_t *buf, const polyvec_t *v, int k, int d) {
    int i;
    size_t poly_bytes;

    if (d == 10) {
        poly_bytes = 320;
    } else {
        poly_bytes = 352; /* d == 11 */
    }

    for (i = 0; i < k; i++) {
        poly_compress(buf + poly_bytes * (size_t)i, &v->vec[i], d);
    }
}

/**
 * @brief Decompress a vector of polynomials from a byte array.
 *
 * @param[out] v   Output polynomial vector structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  k   Module rank.
 * @param[in]  d   Bit length per compressed coefficient (10 or 11).
 */
void polyvec_decompress(polyvec_t *v, const uint8_t *buf, int k, int d) {
    int i;
    size_t poly_bytes;

    if (d == 10) {
        poly_bytes = 320;
    } else {
        poly_bytes = 352;
    }

    for (i = 0; i < k; i++) {
        poly_decompress(&v->vec[i], buf + poly_bytes * (size_t)i, d);
    }
}
