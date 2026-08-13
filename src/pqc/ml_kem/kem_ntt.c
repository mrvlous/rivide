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
 * @file kem_ntt.c
 * @brief ML-KEM NTT, INTT, and basemul implementation with precomputed zetas.
 *
 * Implements Number Theoretic Transform (NTT), inverse NTT, and base polynomial
 * multiplication over Z_q[X]/(X^256 + 1) with q = 3329 per FIPS 203.
 */

#include "rivide/internal/kem_ntt.h"

#include "rivide/internal/kem_reduce.h"

/**
 * @brief Precomputed NTT zetas table for q = 3329.
 *
 * Powers of primitive 256th root of unity in Montgomery form.
 */
const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287,  202,  3158, 622,  1577, 182,  962,  2127, 1855, 1468,
    573,  2004, 264,  383,  2500, 1458, 1727, 3199, 2648, 1017, 732,  608,  1787, 411,  3124, 1758,
    1223, 652,  2777, 1015, 2036, 1491, 3047, 1785, 516,  3321, 3009, 2663, 1711, 2167, 126,  1469,
    2476, 3239, 3058, 830,  107,  1908, 3082, 2378, 2931, 961,  1821, 2604, 448,  2264, 677,  2054,
    2226, 430,  555,  843,  2078, 871,  1550, 105,  422,  587,  177,  3094, 3038, 2869, 1574, 1653,
    3083, 778,  1159, 3182, 2552, 1483, 2727, 1119, 1739, 644,  2457, 349,  418,  329,  3173, 3254,
    817,  1097, 603,  610,  1322, 2044, 1864, 384,  2114, 3193, 1218, 1994, 2455, 220,  2142, 1670,
    2144, 1799, 2051, 794,  1819, 2475, 2459, 478,  3221, 3021, 996,  991,  958,  1869, 1522, 1628};

/**
 * @brief In-place forward NTT transform of a polynomial.
 *
 * @param[in,out] p Polynomial to transform into the NTT domain.
 */
void poly_ntt(poly_t *p) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KEM_N; start += 2 * len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * (int32_t)p->coeffs[j + len]);
                p->coeffs[j + len] = (int16_t)(p->coeffs[j] - t);
                p->coeffs[j] = (int16_t)(p->coeffs[j] + t);
            }
        }
    }
}

/**
 * @brief In-place inverse NTT transform of a polynomial.
 *
 * @param[in,out] p Polynomial to transform from the NTT domain back to spatial form.
 */
void poly_invntt(poly_t *p) {
    static const int16_t zetas_inv[128] = {
        1628, 1522, 1869, 958,  991,  996,  3021, 3221, 478,  2459, 2475, 1819, 794,  2051, 1799,
        2144, 1670, 2142, 220,  2455, 1994, 1218, 3193, 2114, 384,  1864, 2044, 1322, 610,  603,
        1097, 817,  3254, 3173, 329,  418,  349,  2457, 644,  1739, 1119, 2727, 1483, 2552, 3182,
        1159, 778,  3083, 1653, 1574, 2869, 3038, 3094, 177,  587,  422,  105,  1550, 871,  2078,
        843,  555,  430,  2226, 2054, 677,  2264, 448,  2604, 1821, 961,  2931, 2378, 3082, 1908,
        107,  830,  3058, 3239, 2476, 1469, 126,  2167, 1711, 2663, 3009, 3321, 516,  1785, 3047,
        1491, 2036, 1015, 2777, 652,  1223, 1758, 3124, 411,  1787, 608,  732,  1017, 2648, 3199,
        1727, 1458, 2500, 383,  264,  2004, 573,  1468, 1855, 2127, 962,  182,  1577, 622,  3158,
        202,  287,  1422, 1493, 1812, 2970, 2571, 2285};

    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441; /* 128^{-1} mod q in Montgomery form. */

    k = 0;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KEM_N; start += 2 * len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; j++) {
                t = p->coeffs[j];
                p->coeffs[j] = barrett_reduce((int16_t)(t + p->coeffs[j + len]));
                int16_t diff = (int16_t)(p->coeffs[j + len] - t);
                p->coeffs[j + len] = montgomery_reduce((int32_t)zeta * (int32_t)diff);
            }
        }
    }

    for (j = 0; j < KEM_N; j++) {
        p->coeffs[j] = montgomery_reduce((int32_t)f * (int32_t)p->coeffs[j]);
    }
}

/**
 * @brief Pointwise base multiplication of two polynomials in the NTT domain.
 *
 * @param[out] r Output polynomial buffer.
 * @param[in]  a First input polynomial in NTT domain.
 * @param[in]  b Second input polynomial in NTT domain.
 */
void poly_basemul(poly_t *r, const poly_t *a, const poly_t *b) {
    unsigned int i;

    for (i = 0; i < KEM_N / 4; i++) {
        unsigned int idx = 4 * i;
        int16_t zeta = zetas[64 + i];

        /* First basemul in pair. */
        int32_t t0 = montgomery_reduce((int32_t)a->coeffs[idx + 1] * (int32_t)b->coeffs[idx + 1]);
        t0 = montgomery_reduce((int32_t)t0 * (int32_t)zeta);
        int32_t t1 = montgomery_reduce((int32_t)a->coeffs[idx] * (int32_t)b->coeffs[idx]);
        r->coeffs[idx] = (int16_t)(t0 + t1);

        int32_t t2 = montgomery_reduce((int32_t)a->coeffs[idx] * (int32_t)b->coeffs[idx + 1]);
        int32_t t3 = montgomery_reduce((int32_t)a->coeffs[idx + 1] * (int32_t)b->coeffs[idx]);
        r->coeffs[idx + 1] = (int16_t)(t2 + t3);

        /* Second basemul in pair (negated zeta). */
        t0 = montgomery_reduce((int32_t)a->coeffs[idx + 3] * (int32_t)b->coeffs[idx + 3]);
        t0 = montgomery_reduce((int32_t)t0 * (int32_t)(-zeta));
        t1 = montgomery_reduce((int32_t)a->coeffs[idx + 2] * (int32_t)b->coeffs[idx + 2]);
        r->coeffs[idx + 2] = (int16_t)(t0 + t1);

        t2 = montgomery_reduce((int32_t)a->coeffs[idx + 2] * (int32_t)b->coeffs[idx + 3]);
        t3 = montgomery_reduce((int32_t)a->coeffs[idx + 3] * (int32_t)b->coeffs[idx + 2]);
        r->coeffs[idx + 3] = (int16_t)(t2 + t3);
    }
}
