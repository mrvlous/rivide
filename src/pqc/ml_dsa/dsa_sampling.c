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
 * @file dsa_sampling.c
 * @brief ML-DSA polynomial sampling and matrix expansion implementation.
 *
 * Implements ExpandA (SHAKE-128 rejection sampling), ExpandS (eta-bounded
 * sampling via SHAKE-256), ExpandMask (gamma1-bounded sampling), and
 * SampleInBall (challenge polynomial generation) conforming to FIPS 204.
 */

#include "rivide/internal/dsa_sampling.h"

#include "rivide/crypto/sha3.h"
#include "rivide/internal/dsa_ntt.h"
#include "rivide/internal/dsa_packing.h"
#include "rivide/internal/dsa_poly.h"
#include "rivide/internal/dsa_reduce.h"
#include "rivide/utils/mem.h"

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
                          int eta) {
    uint8_t buf[136 * 2]; /* Large enough for rejection sampling. */
    uint8_t extseed[66];  /* Max seed + 2 bytes nonce. */
    rivide_keccak_state_t state;
    unsigned int ctr, pos, i;
    size_t total = seedlen + 2;

    for (i = 0; i < (unsigned int)seedlen; i++) {
        extseed[i] = seed[i];
    }
    extseed[seedlen] = (uint8_t)(nonce & 0xFF);
    extseed[seedlen + 1] = (uint8_t)(nonce >> 8);

    rivide_shake256_init(&state);
    rivide_shake_absorb(&state, extseed, total);
    rivide_shake_squeeze(&state, buf, sizeof(buf));

    ctr = 0;
    pos = 0;
    while (ctr < DSA_N) {
        uint32_t t;

        if (pos >= sizeof(buf)) {
            rivide_shake_squeeze(&state, buf, sizeof(buf));
            pos = 0;
        }

        if (eta == 2) {
            t = (uint32_t)buf[pos++];
            uint32_t d1 = t & 0x0F;
            uint32_t d2 = t >> 4;
            if (d1 < 15 && ctr < DSA_N) {
                d1 = d1 - (5 * (d1 / 5)); /* d1 mod 5 */
                p->coeffs[ctr++] = (int32_t)(2 - d1);
            }
            if (d2 < 15 && ctr < DSA_N) {
                d2 = d2 - (5 * (d2 / 5));
                p->coeffs[ctr++] = (int32_t)(2 - d2);
            }
        } else {
            /* eta == 4 */
            t = (uint32_t)buf[pos++];
            uint32_t d1 = t & 0x0F;
            uint32_t d2 = t >> 4;
            if (d1 < 9 && ctr < DSA_N) {
                p->coeffs[ctr++] = (int32_t)(4 - d1);
            }
            if (d2 < 9 && ctr < DSA_N) {
                p->coeffs[ctr++] = (int32_t)(4 - d2);
            }
        }
    }

    rivide_cleanse(buf, sizeof(buf));
}

/**
 * @brief Sample a uniformly random polynomial from SHAKE-128 (ExpandA).
 *
 * @param[out] p     Output polynomial with coefficients in [0, q-1].
 * @param[in]  seed  32-byte seed for matrix generation (rho).
 * @param[in]  nonce 16-bit nonce encoding matrix row and column indices.
 */
void dsa_poly_uniform(dsa_poly_t *p, const uint8_t seed[32], uint16_t nonce) {
    rivide_keccak_state_t state;
    uint8_t buf[168 * 2];
    uint8_t extseed[34];
    unsigned int ctr, pos, i;

    for (i = 0; i < 32; i++) {
        extseed[i] = seed[i];
    }
    extseed[32] = (uint8_t)(nonce & 0xFF);
    extseed[33] = (uint8_t)(nonce >> 8);

    rivide_shake128_init(&state);
    rivide_shake_absorb(&state, extseed, 34);
    rivide_shake_squeeze(&state, buf, sizeof(buf));

    ctr = 0;
    pos = 0;
    while (ctr < DSA_N) {
        if (pos + 3 > sizeof(buf)) {
            /* Refill the whole buffer; otherwise stale bytes beyond the
             * refilled region would be re-read. */
            rivide_shake_squeeze(&state, buf, sizeof(buf));
            pos = 0;
        }

        uint32_t t =
            ((uint32_t)buf[pos] | ((uint32_t)buf[pos + 1] << 8) | ((uint32_t)buf[pos + 2] << 16)) &
            0x7FFFFF;
        pos += 3;

        if (t < (uint32_t)DSA_Q) {
            p->coeffs[ctr++] = (int32_t)t;
        }
    }
}

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
                             int32_t gamma1) {
    uint8_t buf[640]; /* 5*N/2 bytes for gamma1=2^19. */
    uint8_t extseed[66];
    unsigned int i;
    size_t total = seedlen + 2;
    size_t buflen;

    for (i = 0; i < (unsigned int)seedlen; i++) {
        extseed[i] = seed[i];
    }
    extseed[seedlen] = (uint8_t)(nonce & 0xFF);
    extseed[seedlen + 1] = (uint8_t)(nonce >> 8);

    if (gamma1 == (1 << 17)) {
        buflen = 576; /* 9*N/4 */
    } else {
        buflen = 640; /* 5*N/2 */
    }

    rivide_shake256(buf, buflen, extseed, total);
    dsa_poly_unpack_z(p, buf, gamma1);
    rivide_cleanse(buf, sizeof(buf));
}

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
void dsa_poly_challenge(dsa_poly_t *c, const uint8_t *seed, size_t len, unsigned int tau) {
    rivide_keccak_state_t state;
    uint8_t buf[136];
    unsigned int i, pos;
    uint64_t signs;

    rivide_shake256_init(&state);
    rivide_shake_absorb(&state, seed, len);
    rivide_shake_squeeze(&state, buf, 136);

    signs = 0;
    for (i = 0; i < 8; i++) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (i = 0; i < DSA_N; i++) {
        c->coeffs[i] = 0;
    }

    pos = 8;
    for (i = DSA_N - tau; i < DSA_N; i++) {
        uint8_t byte;
        unsigned int j;

        do {
            if (pos >= 136) {
                rivide_shake_squeeze(&state, buf, 136);
                pos = 0;
            }
            byte = buf[pos++];
            j = (unsigned int)byte;
        } while (j > i);

        c->coeffs[i] = c->coeffs[j];
        c->coeffs[j] = (int32_t)(1 - 2 * (int32_t)(signs & 1));
        signs >>= 1;
    }
}

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
                           int l) {
    dsa_poly_t a_ij, tmp;
    int i, j;

    for (i = 0; i < k; i++) {
        /* t[i] = sum_{j=0}^{l-1} A[i][j] * s[j] */
        for (j = 0; j < l; j++) {
            uint16_t nonce = (uint16_t)((i << 8) | j);
            dsa_poly_uniform(&a_ij, rho, nonce);
            dsa_poly_pointwise(&tmp, &a_ij, &s->vec[j]);
            if (j == 0) {
                unsigned int idx;
                for (idx = 0; idx < DSA_N; idx++) {
                    t->vec[i].coeffs[idx] = tmp.coeffs[idx];
                }
            } else {
                dsa_poly_add(&t->vec[i], &t->vec[i], &tmp);
            }
        }
        dsa_poly_reduce(&t->vec[i]);
    }
}
