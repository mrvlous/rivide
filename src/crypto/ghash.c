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
 * @file ghash.c
 * @brief GHASH multiplication in Galois Field GF(2^128) implementation.
 *
 * Implements field multiplication modulo the reduction polynomial
 * f(x) = x^128 + x^7 + x^2 + x + 1 (reduction constant 0xE1) for AES-GCM
 * authentication tag computation specified in NIST SP 800-38D.
 */

#include "rivide/crypto/ghash.h"

/**
 * @brief Multiply two 128-bit blocks in GF(2^128).
 *
 * Computes x = x * y in GF(2^128) using bitwise multiplication and reduction
 * with polynomial constant 0xE1.
 *
 * @param[in,out] x First 128-bit block (in/out).
 * @param[in]     y Second 128-bit block.
 */
void rivide_ghash_mult(uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    int i, j;

    for (i = 0; i < 16; i++) {
        v[i] = y[i];
    }

    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            uint8_t bit = (uint8_t)((x[i] >> j) & 1);
            uint8_t mask_bit = (uint8_t)(0 - bit);
            int k;
            for (k = 0; k < 16; k++) {
                z[k] ^= (uint8_t)(v[k] & mask_bit);
            }

            {
                uint8_t carry = (uint8_t)(v[15] & 1);
                uint8_t mask_carry = (uint8_t)(0 - carry);
                for (k = 15; k > 0; k--) {
                    v[k] = (uint8_t)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
                }
                v[0] = (uint8_t)((v[0] >> 1) ^ (mask_carry & 0xE1));
            }
        }
    }

    for (i = 0; i < 16; i++) {
        x[i] = z[i];
    }
}

/**
 * @brief Accumulate data blocks into the GHASH authentication tag.
 *
 * Pads incomplete final blocks with zeroes and updates the tag iteratively.
 *
 * @param[in]     h    128-bit hash key H = AES_K(0^128).
 * @param[in]     data Data buffer to authenticate.
 * @param[in]     len  Length of data in bytes.
 * @param[in,out] tag  Accumulated 128-bit tag buffer.
 */
void rivide_ghash_update(const uint8_t h[16], const uint8_t *data, size_t len, uint8_t tag[16]) {
    size_t i, j;
    uint8_t block[16];

    while (len > 0) {
        size_t chunk = (len >= 16) ? 16 : len;

        for (i = 0; i < 16; i++) {
            block[i] = 0;
        }
        for (i = 0; i < chunk; i++) {
            block[i] = data[i];
        }

        for (j = 0; j < 16; j++) {
            tag[j] ^= block[j];
        }
        rivide_ghash_mult(tag, h);

        data += chunk;
        len -= chunk;
    }
}
