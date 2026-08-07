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
 * @file ml_kem.c
 * @brief NIST FIPS 203 ML-KEM implementation (Kyber).
 *
 * Implements the complete ML-KEM key encapsulation mechanism including:
 * - NTT and inverse NTT over Z_q[X]/(X^256 + 1) with q = 3329
 * - Montgomery multiplication for modular arithmetic
 * - Centered Binomial Distribution (CBD) sampling
 * - Polynomial compression and decompression
 * - Matrix expansion via SHAKE-128 (ExpandA)
 * - KeyGen, Encapsulation, and Decapsulation with implicit rejection
 *
 * The implementation is parameterized by a compile-time structure to support
 * both ML-KEM-768 (k=3) and ML-KEM-1024 (k=4) from the same codebase.
 */

#include "rivide/pqc/ml_kem.h"

#include "rivide/crypto/sha3.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

/** @brief Polynomial degree. */
#define N 256

/** @brief Modulus q. */
#define Q 3329

/** @brief Montgomery parameter: R = 2^16 mod q. */
#define MONT_R 2285

/** @brief q^{-1} mod 2^16 (used in Montgomery reduction). */
#define Q_INV 62209

/** @brief Maximum module rank supported. */
#define K_MAX 4

/**
 * @brief Polynomial in Z_q[X]/(X^256 + 1).
 *
 * Coefficients are stored in the range [0, q-1] for normal form, or in
 * Montgomery form for NTT-domain operations.
 */
typedef struct {
    int16_t coeffs[N];
} poly_t;

/**
 * @brief Vector of polynomials (one per module dimension).
 */
typedef struct {
    poly_t vec[K_MAX];
} polyvec_t;

/**
 * @brief Precomputed zeta values (roots of unity) for the NTT.
 *
 * These are the powers of the primitive 512th root of unity (zeta = 17)
 * in Z_q, stored in Montgomery form, in bit-reversed order as required
 * by the iterative NTT butterfly.
 */
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287,  202,  3158, 622,  1577, 182,  962,  2127, 1855, 1468,
    573,  2004, 264,  383,  2500, 1458, 1727, 3199, 2648, 1017, 732,  608,  1787, 411,  3124, 1758,
    1223, 652,  2777, 1015, 2036, 1491, 3047, 1785, 516,  3321, 3009, 2663, 1711, 2167, 126,  1469,
    2476, 3239, 3058, 830,  107,  1908, 3082, 2378, 2931, 961,  1821, 2604, 448,  2264, 677,  2054,
    2226, 430,  555,  843,  2078, 871,  1550, 105,  422,  587,  177,  3094, 3038, 2869, 1574, 1653,
    3083, 778,  1159, 3182, 2552, 1483, 2727, 1119, 1739, 644,  2457, 349,  418,  329,  3173, 3254,
    817,  1097, 603,  610,  1322, 2044, 1864, 384,  2114, 3193, 1218, 1994, 2455, 220,  2142, 1670,
    2144, 1799, 2051, 794,  1819, 2475, 2459, 478,  3221, 3021, 996,  991,  958,  1869, 1522, 1628};

/* Static function forward declarations. */
static void poly_tomont(poly_t *p);

/**
 * @brief Barrett reduction: reduce a 32-bit value mod q = 3329.
 *
 * Uses precomputed Barrett constant to avoid expensive division.
 * Returns a value in [0, q-1].
 *
 * @param[in] a  Value to reduce (must be in [0, 2^15)).
 * @return a mod q.
 */
static int16_t barrett_reduce(int16_t a) {
    int32_t t;
    /* Barrett constant: floor(2^26 / q) + 1 = 20159 */
    t = ((int32_t)20159 * (int32_t)a + (1 << 25)) >> 26;
    t = (int32_t)a - t * Q;
    return (int16_t)t;
}

/**
 * @brief Montgomery reduction: given a 32-bit value, compute a*R^{-1} mod q.
 *
 * @param[in] a  32-bit value to reduce.
 * @return The Montgomery-reduced value in (-q, q).
 */
static int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    /* Use uint32_t arithmetic: uint16_t operands promote to int, and the
     * 16x16-bit product can exceed INT_MAX, which would be undefined. */
    t = (int16_t)((uint32_t)(uint16_t)a * (uint32_t)Q_INV);
    t = (int16_t)((a - (int32_t)t * Q) >> 16);
    return t;
}

/**
 * @brief Conditionally subtract q if the coefficient is >= q.
 *
 * @param[in] a  Coefficient in (-q, 2q).
 * @return Coefficient in [0, q-1].
 */
static int16_t cond_sub_q(int16_t a) {
    a += (a >> 15) & Q;
    a -= Q;
    a += (a >> 15) & Q;
    return a;
}

/**
 * @brief In-place NTT transform of a polynomial.
 *
 * Converts a polynomial from coefficient representation to NTT domain
 * using the iterative Cooley-Tukey butterfly algorithm with precomputed
 * zeta values in bit-reversed order.
 *
 * @param[in,out] p  Polynomial to transform.
 */
static void poly_ntt(poly_t *p) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < N; start += 2 * len) {
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
 * Converts a polynomial from NTT domain back to coefficient representation
 * using the Gentleman-Sande butterfly. The output is multiplied by n^{-1}
 * (in Montgomery form) to complete the transformation.
 *
 * @param[in,out] p  Polynomial to inverse-transform.
 */
static void poly_invntt(poly_t *p) {
    /* Inverse zetas: zetas_inv[k] = zetas[127 - k] (reverse of the forward
     * table), used by the ascending inverse NTT walk per FIPS 203. */
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
    const int16_t f = 1441;

    k = 0;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < N; start += 2 * len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; j++) {
                t = p->coeffs[j];
                p->coeffs[j] = barrett_reduce((int16_t)(t + p->coeffs[j + len]));
                int16_t diff = (int16_t)(p->coeffs[j + len] - t);
                p->coeffs[j + len] = montgomery_reduce((int32_t)zeta * (int32_t)diff);
            }
        }
    }

    for (j = 0; j < N; j++) {
        p->coeffs[j] = montgomery_reduce((int32_t)f * (int32_t)p->coeffs[j]);
    }
}

/**
 * @brief Pointwise multiplication of two polynomials in NTT domain.
 *
 * Computes r = a * b in the NTT domain, where each pair of adjacent
 * coefficients forms a degree-1 polynomial that is multiplied modulo
 * (X^2 - zeta_i) for the appropriate root.
 *
 * @param[out] r  Result polynomial.
 * @param[in]  a  First operand (NTT domain).
 * @param[in]  b  Second operand (NTT domain).
 */
static void poly_basemul(poly_t *r, const poly_t *a, const poly_t *b) {
    unsigned int i;

    for (i = 0; i < N / 4; i++) {
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

/**
 * @brief Add two polynomials: r = a + b.
 */
static void poly_add(poly_t *r, const poly_t *a, const poly_t *b) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
    }
}

/**
 * @brief Subtract two polynomials: r = a - b.
 */
static void poly_sub(poly_t *r, const poly_t *a, const poly_t *b) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] - b->coeffs[i]);
    }
}

/**
 * @brief Reduce all coefficients of a polynomial modulo q.
 */
static void poly_reduce(poly_t *p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
    }
}

/**
 * @brief Convert polynomial to Montgomery domain (multiplies by R mod q).
 */
static void poly_tomont(poly_t *p) {
    /* 1353 = 2^32 mod 3329 */
    const int16_t f = 1353;
    unsigned int i;
    for (i = 0; i < N; i++) {
        p->coeffs[i] = montgomery_reduce((int32_t)p->coeffs[i] * f);
    }
}

/**
 * @brief Convert a polynomial to canonical form [0, q-1].
 */
static void poly_csubq(poly_t *p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        p->coeffs[i] = cond_sub_q(p->coeffs[i]);
    }
}

/**
 * @brief Sample a polynomial from a Centered Binomial Distribution (CBD).
 *
 * Generates coefficients in {-eta, ..., eta} by computing the difference
 * of Hamming weights of bit pairs extracted from the input buffer.
 *
 * @param[out] p    Output polynomial.
 * @param[in]  buf  Input buffer of random bytes (length depends on eta).
 * @param[in]  eta  CBD parameter (2 for ML-KEM-768/1024).
 */
static void poly_cbd(poly_t *p, const uint8_t *buf, int eta) {
    unsigned int i, j;

    if (eta == 2) {
        for (i = 0; i < N / 8; i++) {
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
        /* eta == 3 case (not used in ML-KEM-768/1024, included for completeness). */
        for (i = 0; i < N / 4; i++) {
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

/**
 * @brief Encode a polynomial into bytes (ByteEncode_{12}).
 *
 * Packs each 12-bit coefficient (mod q) into a byte stream.
 *
 * @param[out] buf  Output buffer (384 bytes for 256 12-bit coefficients).
 * @param[in]  p    Polynomial with coefficients in [0, q-1].
 */
static void poly_tobytes(uint8_t *buf, const poly_t *p) {
    unsigned int i;
    for (i = 0; i < N / 2; i++) {
        uint16_t t0 = (uint16_t)((uint16_t)p->coeffs[2 * i] & 0x0FFF);
        uint16_t t1 = (uint16_t)((uint16_t)p->coeffs[2 * i + 1] & 0x0FFF);
        buf[3 * i] = (uint8_t)(t0 & 0xFF);
        buf[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 & 0x0F) << 4));
        buf[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

/**
 * @brief Decode a polynomial from bytes (ByteDecode_{12}).
 *
 * Unpacks 12-bit coefficients from a byte stream.
 *
 * @param[out] p    Output polynomial.
 * @param[in]  buf  Input buffer (384 bytes).
 */
static void poly_frombytes(poly_t *p, const uint8_t *buf) {
    unsigned int i;
    for (i = 0; i < N / 2; i++) {
        p->coeffs[2 * i] =
            (int16_t)(((uint16_t)buf[3 * i] | ((uint16_t)buf[3 * i + 1] << 8)) & 0x0FFF);
        p->coeffs[2 * i + 1] =
            (int16_t)((((uint16_t)buf[3 * i + 1] >> 4) | ((uint16_t)buf[3 * i + 2] << 4)) & 0x0FFF);
    }
}

/**
 * @brief Compress a polynomial coefficient: Compress_d(x).
 *
 * Compresses a coefficient from [0, q-1] to [0, 2^d - 1] via
 * round(2^d / q * x) mod 2^d.
 */
static uint16_t compress_coeff(int16_t x, int d) {
    int16_t c = barrett_reduce(x);
    c = cond_sub_q(c);
    c = (int16_t)(c + ((c >> 15) & Q));
    uint32_t t = (uint32_t)(uint16_t)c;
    t = (t << d) + Q / 2;
    t = t / Q;
    return (uint16_t)(t & ((1u << d) - 1));
}

/**
 * @brief Decompress a polynomial coefficient: Decompress_d(x).
 *
 * Decompresses a coefficient from [0, 2^d - 1] back to [0, q-1] via
 * round(q / 2^d * x).
 */
static int16_t decompress_coeff(uint16_t x, int d) {
    uint32_t t = ((uint32_t)x * Q + (1u << (d - 1))) >> d;
    return (int16_t)t;
}

/**
 * @brief Compress a polynomial and pack into bytes.
 *
 * @param[out] buf  Output buffer.
 * @param[in]  p    Input polynomial (canonical form).
 * @param[in]  d    Compression parameter.
 */
static void poly_compress(uint8_t *buf, const poly_t *p, int d) {
    unsigned int i, j;

    if (d == 4) {
        for (i = 0; i < N / 2; i++) {
            uint8_t t0 = (uint8_t)compress_coeff(p->coeffs[2 * i], d);
            uint8_t t1 = (uint8_t)compress_coeff(p->coeffs[2 * i + 1], d);
            buf[i] = (uint8_t)(t0 | (t1 << 4));
        }
    } else if (d == 5) {
        for (i = 0; i < N / 8; i++) {
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
        for (i = 0; i < N / 4; i++) {
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
        for (i = 0; i < N / 8; i++) {
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
 * @brief Decompress a polynomial from packed bytes.
 *
 * @param[out] p    Output polynomial.
 * @param[in]  buf  Input compressed bytes.
 * @param[in]  d    Compression parameter.
 */
static void poly_decompress(poly_t *p, const uint8_t *buf, int d) {
    unsigned int i, j;

    if (d == 4) {
        for (i = 0; i < N / 2; i++) {
            p->coeffs[2 * i] = decompress_coeff((uint16_t)(buf[i] & 0x0F), d);
            p->coeffs[2 * i + 1] = decompress_coeff((uint16_t)(buf[i] >> 4), d);
        }
    } else if (d == 5) {
        for (i = 0; i < N / 8; i++) {
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
        for (i = 0; i < N / 4; i++) {
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
        for (i = 0; i < N / 8; i++) {
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
 * @brief Encode a message polynomial (1-bit per coefficient).
 *
 * Encodes 32 bytes (256 bits) into a polynomial with coefficients
 * in {0, round(q/2)}, representing the message bits.
 *
 * @param[out] p    Output polynomial.
 * @param[in]  msg  32-byte message.
 */
static void poly_frommsg(poly_t *p, const uint8_t msg[32]) {
    unsigned int i, j;
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 8; j++) {
            p->coeffs[8 * i + j] = decompress_coeff((uint16_t)((msg[i] >> j) & 1), 1);
        }
    }
}

/**
 * @brief Decode a message polynomial back to 32 bytes.
 *
 * Each coefficient is compressed to 1 bit via Compress_1.
 *
 * @param[out] msg  32-byte output message.
 * @param[in]  p    Input polynomial.
 */
static void poly_tomsg(uint8_t msg[32], const poly_t *p) {
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
 * @brief Rejection sampling to generate a polynomial from SHAKE-128 output.
 *
 * Used by ExpandA to sample uniformly random coefficients in [0, q-1]
 * from a SHAKE-128 XOF stream, rejecting values >= q.
 *
 * @param[out] p     Output polynomial.
 * @param[in]  seed  34-byte seed (rho || i || j).
 */
static void poly_uniform(poly_t *p, const uint8_t seed[34]) {
    rivide_keccak_state_t state;
    uint8_t buf[168]; /* One SHAKE-128 block. */
    unsigned int ctr = 0;
    unsigned int pos = 0;
    unsigned int buflen;

    rivide_shake128_init(&state);
    rivide_shake_absorb(&state, seed, 34);
    rivide_shake_squeeze(&state, buf, sizeof(buf));
    buflen = sizeof(buf);

    while (ctr < N) {
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

            if (d1 < Q && ctr < N) {
                p->coeffs[ctr++] = (int16_t)d1;
            }
            if (d2 < Q && ctr < N) {
                p->coeffs[ctr++] = (int16_t)d2;
            }
        }
    }
}

/**
 * @brief Sample a noise polynomial using CBD via SHAKE-256 (PRF).
 *
 * @param[out] p      Output polynomial.
 * @param[in]  seed   32-byte seed (sigma).
 * @param[in]  nonce  Domain separation nonce.
 * @param[in]  eta    CBD parameter.
 */
static void poly_noise(poly_t *p, const uint8_t seed[32], uint8_t nonce, int eta) {
    uint8_t buf[3 * N]; /* Sufficient for eta=2 or eta=3. */
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

/**
 * @brief Encode a polynomial vector to bytes.
 */
static void polyvec_tobytes(uint8_t *buf, const polyvec_t *v, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_tobytes(buf + 384 * i, &v->vec[i]);
    }
}

/**
 * @brief Decode a polynomial vector from bytes.
 */
static void polyvec_frombytes(polyvec_t *v, const uint8_t *buf, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_frombytes(&v->vec[i], buf + 384 * i);
    }
}

/**
 * @brief NTT-transform all polynomials in a vector.
 */
static void polyvec_ntt(polyvec_t *v, int k) {
    int i;
    for (i = 0; i < k; i++) {
        poly_ntt(&v->vec[i]);
    }
}

/**
 * @brief Add two polynomial vectors.
 */

/**
 * @brief Inner product of two polynomial vectors in NTT domain.
 *
 * Computes r = sum_{i=0}^{k-1} a[i] * b[i] in the NTT domain.
 */
static void polyvec_pointwise_acc(poly_t *r, const polyvec_t *a, const polyvec_t *b, int k) {
    int i;
    poly_t tmp;

    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < k; i++) {
        poly_basemul(&tmp, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &tmp);
    }
    poly_reduce(r);
}

/**
 * @brief Compress and pack a polynomial vector.
 */
static void polyvec_compress(uint8_t *buf, const polyvec_t *v, int k, int d) {
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
 * @brief Decompress and unpack a polynomial vector.
 */
static void polyvec_decompress(polyvec_t *v, const uint8_t *buf, int k, int d) {
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

/**
 * @brief Internal K-PKE key generation (Algorithm 12 of FIPS 203).
 *
 * @param[out] pk     Encapsulation key: (t_hat || rho).
 * @param[out] sk     Decapsulation key component: s_hat.
 * @param[in]  seed   32-byte seed (d from FIPS 203).
 * @param[in]  k      Module rank.
 * @param[in]  eta1   CBD parameter for secret vector.
 */
static void ml_kem_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32], int k,
                                    int eta1) {
    uint8_t buf[64];
    uint8_t g_input[33];
    uint8_t rho[32], sigma[32];
    polyvec_t a_row, s, e, t;
    uint8_t extseed[34];
    int i, j;
    uint8_t nonce = 0;

    /* G(d || k) -> (rho, sigma), with the module rank byte k appended
     * (FIPS 203 Algorithm 16). */
    for (i = 0; i < 32; i++) {
        g_input[i] = seed[i];
    }
    g_input[32] = (uint8_t)k;
    rivide_sha3_512(buf, g_input, 33);
    for (i = 0; i < 32; i++) {
        rho[i] = buf[i];
        sigma[i] = buf[32 + i];
    }

    /* Sample secret vector s from CBD(sigma, nonce). */
    for (i = 0; i < k; i++) {
        poly_noise(&s.vec[i], sigma, nonce++, eta1);
    }

    /* Sample error vector e from CBD(sigma, nonce). */
    for (i = 0; i < k; i++) {
        poly_noise(&e.vec[i], sigma, nonce++, eta1);
    }

    /* NTT(s), NTT(e). */
    polyvec_ntt(&s, k);
    polyvec_ntt(&e, k);

    /* Compute t = A * s + e in NTT domain. */
    for (i = 0; i < k; i++) {
        /* Generate row i of matrix A. */
        for (j = 0; j < k; j++) {
            unsigned int idx;
            for (idx = 0; idx < 32; idx++) {
                extseed[idx] = rho[idx];
            }
            extseed[32] = (uint8_t)j;
            extseed[33] = (uint8_t)i;
            poly_uniform(&a_row.vec[j], extseed);
        }

        polyvec_pointwise_acc(&t.vec[i], &a_row, &s, k);
        poly_tomont(&t.vec[i]);
        poly_add(&t.vec[i], &t.vec[i], &e.vec[i]);
    }

    for (i = 0; i < k; i++) {
        poly_reduce(&s.vec[i]);
        poly_csubq(&s.vec[i]);
        poly_reduce(&t.vec[i]);
        poly_csubq(&t.vec[i]);
    }

    /* Pack public key: t || rho. */
    polyvec_tobytes(pk, &t, k);
    for (i = 0; i < 32; i++) {
        pk[384 * k + i] = rho[i];
    }

    /* Pack secret key component: s. */
    polyvec_tobytes(sk, &s, k);

    /* Cleanse intermediates. */
    rivide_cleanse(buf, sizeof(buf));
    rivide_cleanse(sigma, sizeof(sigma));
    rivide_cleanse(&s, sizeof(s));
    rivide_cleanse(&e, sizeof(e));
}

/**
 * @brief Internal K-PKE encryption (Algorithm 13 of FIPS 203).
 *
 * @param[out] ct    Ciphertext.
 * @param[in]  pk    Public key.
 * @param[in]  msg   32-byte message (the randomized pre-key m).
 * @param[in]  coins 32-byte randomness (r from FIPS 203).
 * @param[in]  k     Module rank.
 * @param[in]  eta1  CBD parameter for r vector.
 * @param[in]  eta2  CBD parameter for noise.
 * @param[in]  du    Compression parameter for u.
 * @param[in]  dv    Compression parameter for v.
 */
static void ml_kem_encrypt_internal(uint8_t *ct, const uint8_t *pk, const uint8_t msg[32],
                                    const uint8_t coins[32], int k, int eta1, int eta2, int du,
                                    int dv) {
    polyvec_t r_vec, e1, at_row, u;
    poly_t e2, v_poly, msg_poly;
    uint8_t rho[32];
    uint8_t extseed[34];
    int i, j;
    uint8_t nonce = 0;
    size_t u_bytes;

    /* Extract rho from public key. */
    for (i = 0; i < 32; i++) {
        rho[i] = pk[384 * k + i];
    }

    /* Sample r from CBD(coins, nonce). */
    for (i = 0; i < k; i++) {
        poly_noise(&r_vec.vec[i], coins, nonce++, eta1);
    }

    /* Sample e1 from CBD(coins, nonce). */
    for (i = 0; i < k; i++) {
        poly_noise(&e1.vec[i], coins, nonce++, eta2);
    }

    /* Sample e2 from CBD(coins, nonce). */
    poly_noise(&e2, coins, nonce++, eta2);

    polyvec_ntt(&r_vec, k);

    /* Compute u = A^T * r + e1. */
    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            unsigned int idx;
            for (idx = 0; idx < 32; idx++) {
                extseed[idx] = rho[idx];
            }
            /* Transpose: swap indices. */
            extseed[32] = (uint8_t)i;
            extseed[33] = (uint8_t)j;
            poly_uniform(&at_row.vec[j], extseed);
        }

        polyvec_pointwise_acc(&u.vec[i], &at_row, &r_vec, k);
        poly_invntt(&u.vec[i]);
        poly_add(&u.vec[i], &u.vec[i], &e1.vec[i]);
    }

    /* Compute v = t^T * r + e2 + msg. */
    {
        polyvec_t t_hat;
        polyvec_frombytes(&t_hat, pk, k);
        polyvec_pointwise_acc(&v_poly, &t_hat, &r_vec, k);
        poly_invntt(&v_poly);
    }

    poly_add(&v_poly, &v_poly, &e2);
    poly_frommsg(&msg_poly, msg);
    poly_add(&v_poly, &v_poly, &msg_poly);

    for (i = 0; i < k; i++) {
        poly_reduce(&u.vec[i]);
        poly_csubq(&u.vec[i]);
    }
    poly_reduce(&v_poly);
    poly_csubq(&v_poly);

    /* Pack ciphertext: Compress(u, du) || Compress(v, dv). */
    if (du == 10) {
        u_bytes = 320 * (size_t)k;
    } else {
        u_bytes = 352 * (size_t)k;
    }
    polyvec_compress(ct, &u, k, du);
    poly_compress(ct + u_bytes, &v_poly, dv);

    rivide_cleanse(&r_vec, sizeof(r_vec));
    rivide_cleanse(&e1, sizeof(e1));
    rivide_cleanse(&e2, sizeof(e2));
}

/**
 * @brief Internal ML-KEM decryption (K-PKE.Decrypt).
 */
static void ml_kem_decrypt_internal(uint8_t msg[32], const uint8_t *ct, const uint8_t *sk, int k,
                                    int du, int dv) {
    polyvec_t u, s_hat;
    poly_t v_poly, tmp;
    size_t u_bytes;

    if (du == 10) {
        u_bytes = 320 * (size_t)k;
    } else {
        u_bytes = 352 * (size_t)k;
    }

    polyvec_decompress(&u, ct, k, du);
    poly_decompress(&v_poly, ct + u_bytes, dv);

    polyvec_frombytes(&s_hat, sk, k);

    polyvec_ntt(&u, k);
    polyvec_pointwise_acc(&tmp, &s_hat, &u, k);
    poly_invntt(&tmp);

    poly_sub(&v_poly, &v_poly, &tmp);
    poly_reduce(&v_poly);
    poly_csubq(&v_poly);

    poly_tomsg(msg, &v_poly);

    rivide_cleanse(&s_hat, sizeof(s_hat));
    rivide_cleanse(&u, sizeof(u));
    rivide_cleanse(&v_poly, sizeof(v_poly));
    rivide_cleanse(&tmp, sizeof(tmp));
}

/**
 * @brief Full ML-KEM key generation (Algorithm 16 of FIPS 203).
 *
 * Generates both the internal K-PKE keypair and the full ML-KEM
 * decapsulation key structure: sk = (s_hat || pk || H(pk) || z).
 */
static rivide_status_t ml_kem_keygen(uint8_t *pk, uint8_t *sk, int k, int eta1, size_t pk_bytes,
                                     size_t sk_bytes) {
    uint8_t d[32], z[32];
    rivide_status_t ret;
    size_t s_hat_bytes = 384 * (size_t)k;

    (void)sk_bytes;

    ret = rivide_randombytes(d, 32);
    if (ret != RIVIDE_SUCCESS) {
        return ret;
    }

    ret = rivide_randombytes(z, 32);
    if (ret != RIVIDE_SUCCESS) {
        rivide_cleanse(d, sizeof(d));
        return ret;
    }

    /* Generate K-PKE keypair. */
    ml_kem_keypair_internal(pk, sk, d, k, eta1);

    /* Full decapsulation key layout: s_hat || pk || H(pk) || z */
    {
        size_t offset = s_hat_bytes;
        unsigned int i;

        /* Copy pk into sk. */
        for (i = 0; i < pk_bytes; i++) {
            sk[offset + i] = pk[i];
        }
        offset += pk_bytes;

        /* H(pk) */
        rivide_sha3_256(sk + offset, pk, pk_bytes);
        offset += 32;

        /* z */
        for (i = 0; i < 32; i++) {
            sk[offset + i] = z[i];
        }
    }

    rivide_cleanse(d, sizeof(d));
    rivide_cleanse(z, sizeof(z));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Full ML-KEM encapsulation (Algorithm 17 of FIPS 203).
 *
 * Generates a random message m, derives (K, r) = G(m || H(pk)),
 * encrypts m under pk with randomness r to get ct, and outputs
 * the shared secret K.
 */
static rivide_status_t ml_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, int k, int eta1,
                                     int eta2, int du, int dv, size_t pk_bytes) {
    uint8_t m[32], h_pk[32];
    uint8_t g_input[64], g_output[64];
    rivide_status_t ret;
    unsigned int i;

    if (!ct || !ss || !pk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    ret = rivide_randombytes(m, 32);
    if (ret != RIVIDE_SUCCESS) {
        return ret;
    }

    /* H(pk) */
    rivide_sha3_256(h_pk, pk, pk_bytes);

    /* G(m || H(pk)) -> (K, r) */
    for (i = 0; i < 32; i++) {
        g_input[i] = m[i];
        g_input[32 + i] = h_pk[i];
    }
    rivide_sha3_512(g_output, g_input, 64);

    /* Encrypt m using r. */
    ml_kem_encrypt_internal(ct, pk, m, g_output + 32, k, eta1, eta2, du, dv);

    /* Output shared secret K. */
    for (i = 0; i < 32; i++) {
        ss[i] = g_output[i];
    }

    rivide_cleanse(m, sizeof(m));
    rivide_cleanse(g_input, sizeof(g_input));
    rivide_cleanse(g_output, sizeof(g_output));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Full ML-KEM decapsulation (Algorithm 18 of FIPS 203).
 *
 * Decrypts the ciphertext to recover m', re-derives (K', r') = G(m' || H(pk)),
 * re-encrypts under pk with r' to get ct', and uses constant-time comparison
 * of ct and ct' to select between K' and a pseudorandom implicit rejection
 * value derived from z.
 */
static rivide_status_t ml_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, int k,
                                     int eta1, int eta2, int du, int dv, size_t pk_bytes,
                                     size_t ct_bytes) {
    size_t s_hat_bytes = 384 * (size_t)k;
    const uint8_t *pk = sk + s_hat_bytes;
    const uint8_t *h_pk = pk + pk_bytes;
    const uint8_t *z = h_pk + 32;

    uint8_t m_prime[32];
    uint8_t g_input[64], g_output[64];
    uint8_t ct_prime[1568]; /* Max ciphertext size (ML-KEM-1024). */
    uint8_t k_reject[32];
    unsigned int i;
    int cmp;

    if (!ss || !ct || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* Decrypt ct -> m'. */
    ml_kem_decrypt_internal(m_prime, ct, sk, k, du, dv);

    /* G(m' || H(pk)) -> (K', r'). */
    for (i = 0; i < 32; i++) {
        g_input[i] = m_prime[i];
        g_input[32 + i] = h_pk[i];
    }
    rivide_sha3_512(g_output, g_input, 64);

    /* Re-encrypt m' with r'. */
    ml_kem_encrypt_internal(ct_prime, pk, m_prime, g_output + 32, k, eta1, eta2, du, dv);

    /* Compute implicit rejection value: J(z || ct). */
    {
        rivide_keccak_state_t jstate;
        rivide_shake256_init(&jstate);
        rivide_shake_absorb(&jstate, z, 32);
        rivide_shake_absorb(&jstate, ct, ct_bytes);
        rivide_shake_squeeze(&jstate, k_reject, 32);
    }

    /* Constant-time comparison of ct and ct'. */
    cmp = rivide_ct_memcmp(ct, ct_prime, ct_bytes);

    /* Select K' if ct == ct', otherwise select K_reject. */
    rivide_ct_select(ss, g_output, k_reject, 32, cmp);

    rivide_cleanse(m_prime, sizeof(m_prime));
    rivide_cleanse(g_input, sizeof(g_input));
    rivide_cleanse(g_output, sizeof(g_output));
    rivide_cleanse(ct_prime, ct_bytes);
    rivide_cleanse(k_reject, sizeof(k_reject));

    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_ml_kem_768_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }
    return ml_kem_keygen(pk, sk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_PK_BYTES, RIVIDE_ML_KEM_768_SK_BYTES);
}

rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return ml_kem_encaps(ct, ss, pk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_ETA2, RIVIDE_ML_KEM_768_DU, RIVIDE_ML_KEM_768_DV,
                         RIVIDE_ML_KEM_768_PK_BYTES);
}

rivide_status_t rivide_ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return ml_kem_decaps(ss, ct, sk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_ETA2, RIVIDE_ML_KEM_768_DU, RIVIDE_ML_KEM_768_DV,
                         RIVIDE_ML_KEM_768_PK_BYTES, RIVIDE_ML_KEM_768_CT_BYTES);
}

rivide_status_t rivide_ml_kem_1024_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }
    return ml_kem_keygen(pk, sk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_PK_BYTES, RIVIDE_ML_KEM_1024_SK_BYTES);
}

rivide_status_t rivide_ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return ml_kem_encaps(ct, ss, pk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_ETA2, RIVIDE_ML_KEM_1024_DU, RIVIDE_ML_KEM_1024_DV,
                         RIVIDE_ML_KEM_1024_PK_BYTES);
}

rivide_status_t rivide_ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return ml_kem_decaps(ss, ct, sk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_ETA2, RIVIDE_ML_KEM_1024_DU, RIVIDE_ML_KEM_1024_DV,
                         RIVIDE_ML_KEM_1024_PK_BYTES, RIVIDE_ML_KEM_1024_CT_BYTES);
}
