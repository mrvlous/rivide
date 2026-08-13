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
 * @file kem_sampling.c
 * @brief ML-KEM uniform rejection sampling (ExpandA) and noise sampling (PRF).
 *
 * Implements SHAKE-128 rejection sampling for matrix A generation and PRF noise
 * polynomial sampling via SHAKE-256 and CBD as specified in FIPS 203.
 */

#include "rivide/internal/kem_sampling.h"

#include "rivide/crypto/sha3.h"
#include "rivide/internal/kem_cbd.h"
#include "rivide/utils/mem.h"

/**
 * @brief Sample a uniformly random polynomial from SHAKE-128 (ExpandA).
 *
 * @param[out] p    Output polynomial structure.
 * @param[in]  seed 34-byte seed consisting of rho (32 bytes) and matrix coordinates.
 */
void poly_uniform(poly_t *p, const uint8_t seed[34]) {
    rivide_keccak_state_t state;
    uint8_t buf[168]; /* One SHAKE-128 block. */
    unsigned int ctr = 0;
    unsigned int pos = 0;
    unsigned int buflen;

    rivide_shake128_init(&state);
    rivide_shake_absorb(&state, seed, 34);
    rivide_shake_squeeze(&state, buf, sizeof(buf));
    buflen = sizeof(buf);

    while (ctr < KEM_N) {
        if (pos + 3 > buflen) {
            /* Squeeze another block. */
            rivide_shake_squeeze(&state, buf, sizeof(buf));
            buflen = sizeof(buf);
            pos = 0;
        }

        {
            uint16_t d1 = (uint16_t)(((uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x0FFF);
            uint16_t d2 =
                (uint16_t)((((uint16_t)buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) &
                           0x0FFF);
            pos += 3;

            if (d1 < KEM_Q && ctr < KEM_N) {
                p->coeffs[ctr++] = (int16_t)d1;
            }
            if (d2 < KEM_Q && ctr < KEM_N) {
                p->coeffs[ctr++] = (int16_t)d2;
            }
        }
    }
}

/**
 * @brief Sample a noise polynomial from SHAKE-256 and CBD (PRF).
 *
 * @param[out] p     Output noise polynomial.
 * @param[in]  seed  32-byte seed (sigma or coins).
 * @param[in]  nonce Nonce byte counter.
 * @param[in]  eta   CBD parameter (2 or 3).
 */
void poly_noise(poly_t *p, const uint8_t seed[32], uint8_t nonce, int eta) {
    uint8_t buf[3 * KEM_N]; /* Sufficient for eta=2 or eta=3. */
    uint8_t extseed[33];
    size_t buflen = (size_t)(64 * eta);
    unsigned int i;

    for (i = 0; i < 32; i++) {
        extseed[i] = seed[i];
    }
    extseed[32] = nonce;

    rivide_shake256(buf, buflen, extseed, 33);
    poly_cbd(p, buf, eta);
    rivide_cleanse(buf, sizeof(buf));
}
