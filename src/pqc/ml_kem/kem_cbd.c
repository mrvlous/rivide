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
 * @file kem_cbd.c
 * @brief ML-KEM Centered Binomial Distribution (CBD) sampling logic.
 *
 * Implements deterministic sampling of noise polynomials from uniform byte arrays
 * for eta = 2 (ML-KEM-768 / ML-KEM-1024) and eta = 3 (ML-KEM-512) per FIPS 203.
 */

#include "rivide/internal/kem_cbd.h"

/**
 * @brief Sample a polynomial from a Centered Binomial Distribution (CBD_eta).
 *
 * @param[out] p   Output polynomial with coefficients in [-eta, eta].
 * @param[in]  buf Input byte stream (64*eta bytes).
 * @param[in]  eta CBD parameter (2 or 3).
 */
void poly_cbd(poly_t *p, const uint8_t *buf, int eta) {
    unsigned int i, j;

    if (eta == 2) {
        for (i = 0; i < KEM_N / 8; i++) {
            uint32_t t = (uint32_t)buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8) |
                         ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);

            for (j = 0; j < 8; j++) {
                int16_t a = (int16_t)((t >> (4 * j)) & 0x03);
                int16_t b_val = (int16_t)((t >> (4 * j + 2)) & 0x03);
                /* Compute popcount of 2-bit fields. */
                a = (int16_t)((a & 1) + ((a >> 1) & 1));
                b_val = (int16_t)((b_val & 1) + ((b_val >> 1) & 1));
                p->coeffs[8 * i + j] = (int16_t)(a - b_val);
            }
        }
    } else {
        /* eta == 3 case */
        for (i = 0; i < KEM_N / 4; i++) {
            uint32_t t = (uint32_t)buf[3 * i] | ((uint32_t)buf[3 * i + 1] << 8) |
                         ((uint32_t)buf[3 * i + 2] << 16);

            for (j = 0; j < 4; j++) {
                int16_t a = (int16_t)((t >> (6 * j)) & 0x07);
                int16_t b_val = (int16_t)((t >> (6 * j + 3)) & 0x07);
                a = (int16_t)((a & 1) + ((a >> 1) & 1) + ((a >> 2) & 1));
                b_val = (int16_t)((b_val & 1) + ((b_val >> 1) & 1) + ((b_val >> 2) & 1));
                p->coeffs[4 * i + j] = (int16_t)(a - b_val);
            }
        }
    }
}
