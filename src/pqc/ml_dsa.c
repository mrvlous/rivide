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
 * @file ml_dsa.c
 * @brief NIST FIPS 204 ML-DSA implementation (Dilithium).
 *
 * Implements the complete ML-DSA digital signature scheme including:
 * - NTT and inverse NTT over Z_q[X]/(X^256 + 1) with q = 8380417
 * - Montgomery multiplication for modular arithmetic
 * - Power2Round, Decompose, MakeHint, UseHint rounding functions
 * - SampleInBall challenge polynomial generation
 * - ExpandA, ExpandS, ExpandMask sampling functions
 * - KeyGen, Sign (with rejection sampling), and Verify
 *
 * The implementation is parameterized to support both ML-DSA-65 (k=6, l=5)
 * and ML-DSA-87 (k=8, l=7) from the same codebase.
 */

#include "rivide/pqc/ml_dsa.h"

#include "rivide/crypto/sha3.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

/** @brief Polynomial degree. */
#define N 256

/** @brief Modulus q = 8380417 = 2^23 - 2^13 + 1. */
#define Q 8380417

/** @brief Montgomery parameter R = 2^32 mod q. */
#define MONT 4193792

/** @brief q^{-1} mod 2^32 (for Montgomery reduction). */
#define QINV 58728449

/** @brief Power2Round dropping bits. */
#define D_BITS 13

/** @brief Maximum module rank k. */
#define K_MAX 8

/** @brief Maximum l dimension. */
#define L_MAX 7

/**
 * @brief Polynomial in Z_q[X]/(X^256 + 1) for Dilithium.
 *
 * Coefficients are stored as signed 32-bit integers to accommodate
 * the larger modulus q = 8380417.
 */
typedef struct {
    int32_t coeffs[N];
} dsa_poly_t;

/**
 * @brief Vector of k polynomials.
 */
typedef struct {
    dsa_poly_t vec[K_MAX];
} dsa_polyveck_t;

/**
 * @brief Vector of l polynomials.
 */
typedef struct {
    dsa_poly_t vec[L_MAX];
} dsa_polyvecl_t;

/**
 * @brief NTT zeta table for q = 8380417.
 *
 * Precomputed roots of unity in Montgomery form, in bit-reversed order
 * for the iterative NTT butterfly. The primitive 512th root of unity
 * modulo q is zeta = 1753.
 */
static const int32_t dsa_zetas[N] = {
    0,        25847,    -2608894, -518909,  237124,   -777960,  -876248,  466468,   1826347,
    2353451,  -359251,  -2091905, 3119733,  -2884855, 3111497,  2680103,  2725464,  1024112,
    -1079900, 3585928,  -549488,  -1119584, 2619752,  -2108549, -2118186, -3859737, -1399561,
    -3277672, 1757237,  -19422,   4010497,  280005,   2706023,  95776,    3077325,  3530437,
    -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716, 3574422,  -2867647, 3539968,
    -300467,  2348700,  -539299,  -1699267, -1643818, 3505694,  -3821735, 3507263,  -2140649,
    -1600420, 3699596,  811944,   531354,   954230,   3881043,  3900724,  -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,  2176455,  -1585221,
    -1257611, 1939314,  -4083598, -1000202, -3190144, -3157330, -3632928, 126922,   3412210,
    -983419,  2147896,  2715295,  -2967645, -3693493, -411027,  -2477047, -671102,  -1228525,
    -22981,   -1308169, -381987,  1349076,  1852771,  -1430430, -3343383, 264944,   508951,
    3097992,  44288,    -1100098, 904516,   3958618,  -3724342, -8578,    1653064,  -3249728,
    2389356,  -210977,  759969,   -1316856, 189548,   -3553272, 3159746,  -1851402, -2409325,
    -177440,  1315589,  1341330,  1285669,  -1584928, -812732,  -1439742, -3019102, -3881060,
    -3628969, 3839961,  2091667,  3407706,  2316500,  3817976,  -3342478, 2244091,  -2446433,
    -3562462, 266997,   2434439,  -1235728, 3513181,  -3520352, -3759364, -1197226, -3193378,
    900702,   1859098,  909542,   819034,   495491,   -1613174, -43260,   -522500,  -655327,
    -3122442, 2031748,  3207046,  -3556995, -525098,  -768622,  -3595838, 342297,   286988,
    -2437823, 4108315,  3437287,  -3342277, 1735879,  203044,   2842341,  2691481,  -2590150,
    1265009,  4055324,  1247620,  2486353,  1595974,  -3767016, 1250494,  2635921,  -3548272,
    -2994039, 1869119,  1903435,  -1050970, -1333058, 1237275,  -3318210, -1430225, -451100,
    1312455,  3306115,  -1962642, -1279661, 1917081,  -2546312, -1374803, 1500165,  777191,
    2235880,  3406031,  -542412,  -2831860, -1671176, -1846953, -2584293, -3724270, 594136,
    -3776993, -2013608, 2432395,  2454455,  -164721,  1957272,  3369112,  185531,   -1207385,
    -3183426, 162844,   1616392,  3014001,  810149,   1652634,  -3694233, -1799107, -3038916,
    3523897,  3866901,  269760,   2213111,  -975884,  1717735,  472078,   -426683,  1723600,
    -1803090, 1910376,  -1667432, -1104333, -260646,  -3833893, -2939036, -2235985, -420899,
    -2286327, 183443,   -976891,  1612842,  -3545687, -554416,  3919660,  -48306,   -1362209,
    3937738,  1400424,  -846154,  1976782};

/**
 * @brief Montgomery reduction for Dilithium (32-bit).
 *
 * Given a 64-bit value a, computes a * R^{-1} mod q where R = 2^32.
 *
 * @param[in] a  64-bit value to reduce.
 * @return Value in (-q, q).
 */
static int32_t dsa_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((uint32_t)a * (uint32_t)QINV);
    t = (int32_t)((a - (int64_t)t * Q) >> 32);
    return t;
}

/**
 * @brief Reduce a coefficient modulo q to the centered range.
 *
 * @param[in] a  Coefficient to reduce.
 * @return Value in (-q/2, q/2].
 */
static int32_t dsa_reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

/**
 * @brief Conditionally add q if coefficient is negative.
 *
 * @param[in] a  Coefficient in (-q, q).
 * @return Coefficient in [0, q-1].
 */
static int32_t dsa_caddq(int32_t a) {
    a += (a >> 31) & Q;
    return a;
}

/**
 * @brief In-place NTT for Dilithium polynomials.
 */
static void dsa_poly_ntt(dsa_poly_t *p) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len >= 1; len >>= 1) {
        for (start = 0; start < N; start += 2 * len) {
            zeta = dsa_zetas[++k];
            for (j = start; j < start + len; j++) {
                t = dsa_montgomery_reduce((int64_t)zeta * p->coeffs[j + len]);
                p->coeffs[j + len] = p->coeffs[j] - t;
                p->coeffs[j] = p->coeffs[j] + t;
            }
        }
    }
}

/**
 * @brief In-place inverse NTT for Dilithium polynomials.
 */
static void dsa_poly_invntt(dsa_poly_t *p) {
    unsigned int len, start, j, k;
    int32_t zeta, t;
    const int32_t f = 41978; /* 256^{-1} mod q in Montgomery form. */

    k = 256;
    for (len = 1; len < N; len <<= 1) {
        for (start = 0; start < N; start += 2 * len) {
            zeta = dsa_zetas[--k];
            for (j = start; j < start + len; j++) {
                t = p->coeffs[j];
                p->coeffs[j] = t + p->coeffs[j + len];
                int32_t diff = p->coeffs[j + len] - t;
                p->coeffs[j + len] = dsa_montgomery_reduce((int64_t)zeta * diff);
            }
        }
    }

    for (j = 0; j < N; j++) {
        p->coeffs[j] = dsa_montgomery_reduce((int64_t)f * p->coeffs[j]);
    }
}

/**
 * @brief Pointwise multiplication of two polynomials in NTT domain.
 */
static void dsa_poly_pointwise(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        r->coeffs[i] = dsa_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

/**
 * @brief Add two polynomials: r = a + b.
 */
static void dsa_poly_add(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * @brief Subtract two polynomials: r = a - b.
 */
static void dsa_poly_sub(dsa_poly_t *r, const dsa_poly_t *a, const dsa_poly_t *b) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * @brief Reduce all coefficients modulo q.
 */
static void dsa_poly_reduce(dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        p->coeffs[i] = dsa_reduce32(p->coeffs[i]);
    }
}

/**
 * @brief Add q to negative coefficients.
 */
static void dsa_poly_caddq(dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        p->coeffs[i] = dsa_caddq(p->coeffs[i]);
    }
}

/**
 * @brief Power2Round: decompose t into (t1, t0) where t = t1*2^d + t0.
 *
 * @param[in]  a   Coefficient in [0, q-1].
 * @param[out] a0  Low bits t0 in [-(2^(d-1)), 2^(d-1)].
 * @return t1 = (t - t0) / 2^d.
 */
static int32_t power2round(int32_t a, int32_t *a0) {
    int32_t a1;
    a1 = (a + (1 << (D_BITS - 1)) - 1) >> D_BITS;
    *a0 = a - (a1 << D_BITS);
    return a1;
}

/**
 * @brief Decompose: decompose a into (a1, a0) where a = a1*alpha + a0.
 *
 * @param[in]  a       Coefficient in [0, q-1].
 * @param[out] a0      Low part in (-alpha/2, alpha/2].
 * @param[in]  gamma2  The alpha/2 parameter.
 * @return a1, the high part.
 */
static int32_t decompose(int32_t a, int32_t *a0, int32_t gamma2) {
    int32_t a1;
    a1 = (a + 127) >> 7;

    if (gamma2 == (Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        /* gamma2 == (Q-1)/88 */
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    *a0 = a - a1 * 2 * gamma2;
    *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
    return a1;
}

/**
 * @brief Compute the hint bit for one coefficient.
 *
 * @param[in] a0      Low part from Decompose.
 * @param[in] a1      High part from Decompose.
 * @param[in] gamma2  Decomposition parameter.
 * @return 1 if a hint is needed, 0 otherwise.
 */
static unsigned int make_hint(int32_t a0, int32_t a1, int32_t gamma2) {
    if (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Apply the hint to recover the correct high bits.
 *
 * @param[in] a       Original coefficient.
 * @param[in] hint    Hint bit (0 or 1).
 * @param[in] gamma2  Decomposition parameter.
 * @return Corrected high bits.
 */
static int32_t use_hint(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;

    a1 = decompose(a, &a0, gamma2);

    if (hint == 0) {
        return a1;
    }

    if (gamma2 == (Q - 1) / 32) {
        if (a0 > 0) {
            return (a1 + 1) & 15;
        }
        return (a1 - 1) & 15;
    }

    /* gamma2 == (Q-1)/88 */
    if (a0 > 0) {
        return (a1 == 43) ? 0 : a1 + 1;
    }
    return (a1 == 0) ? 43 : a1 - 1;
}

/**
 * @brief Check if the infinity norm of a polynomial exceeds a bound.
 *
 * @param[in] p      Polynomial.
 * @param[in] bound  Bound to check against.
 * @return 1 if any coefficient has absolute value >= bound, 0 otherwise.
 */
static int dsa_poly_chknorm(const dsa_poly_t *p, int32_t bound) {
    unsigned int i;
    int32_t t;

    if (bound > (Q / 2)) {
        return 1;
    }

    for (i = 0; i < N; i++) {
        t = dsa_reduce32(p->coeffs[i]);
        if (t < 0) {
            t = -t;
        }
        if (t >= bound) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Pack t1 polynomial (10 bits per coefficient) into bytes.
 *
 * @param[out] buf  Output buffer (320 bytes per polynomial).
 * @param[in]  p    Polynomial with coefficients in [0, 2^10 - 1].
 */
static void dsa_poly_pack_t1(uint8_t *buf, const dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < N / 4; i++) {
        buf[5 * i] = (uint8_t)(p->coeffs[4 * i] & 0xFF);
        buf[5 * i + 1] = (uint8_t)((p->coeffs[4 * i] >> 8) | ((p->coeffs[4 * i + 1] & 0x3F) << 2));
        buf[5 * i + 2] =
            (uint8_t)((p->coeffs[4 * i + 1] >> 6) | ((p->coeffs[4 * i + 2] & 0x0F) << 4));
        buf[5 * i + 3] =
            (uint8_t)((p->coeffs[4 * i + 2] >> 4) | ((p->coeffs[4 * i + 3] & 0x03) << 6));
        buf[5 * i + 4] = (uint8_t)(p->coeffs[4 * i + 3] >> 2);
    }
}

/**
 * @brief Unpack t1 polynomial from bytes.
 */
static void dsa_poly_unpack_t1(dsa_poly_t *p, const uint8_t *buf) {
    unsigned int i;
    for (i = 0; i < N / 4; i++) {
        p->coeffs[4 * i] = ((uint32_t)buf[5 * i] | ((uint32_t)buf[5 * i + 1] << 8)) & 0x3FF;
        p->coeffs[4 * i + 1] =
            (((uint32_t)buf[5 * i + 1] >> 2) | ((uint32_t)buf[5 * i + 2] << 6)) & 0x3FF;
        p->coeffs[4 * i + 2] =
            (((uint32_t)buf[5 * i + 2] >> 4) | ((uint32_t)buf[5 * i + 3] << 4)) & 0x3FF;
        p->coeffs[4 * i + 3] =
            (((uint32_t)buf[5 * i + 3] >> 6) | ((uint32_t)buf[5 * i + 4] << 2)) & 0x3FF;
    }
}

/**
 * @brief Pack an eta-bounded polynomial into bytes.
 *
 * Coefficients are in [-eta, eta]; they are shifted to [0, 2*eta] for packing.
 */
static void dsa_poly_pack_eta(uint8_t *buf, const dsa_poly_t *p, int eta) {
    unsigned int i;

    if (eta == 2) {
        for (i = 0; i < N / 8; i++) {
            uint8_t t[8];
            unsigned int j;
            for (j = 0; j < 8; j++) {
                t[j] = (uint8_t)(eta - p->coeffs[8 * i + j]);
            }
            buf[3 * i] = (uint8_t)(t[0] | (t[1] << 3) | (t[2] << 6));
            buf[3 * i + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
            buf[3 * i + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
        }
    } else {
        /* eta == 4 */
        for (i = 0; i < N / 2; i++) {
            uint8_t t0 = (uint8_t)(eta - p->coeffs[2 * i]);
            uint8_t t1 = (uint8_t)(eta - p->coeffs[2 * i + 1]);
            buf[i] = (uint8_t)(t0 | (t1 << 4));
        }
    }
}

/**
 * @brief Unpack an eta-bounded polynomial from bytes.
 */
static void dsa_poly_unpack_eta(dsa_poly_t *p, const uint8_t *buf, int eta) {
    unsigned int i;

    if (eta == 2) {
        for (i = 0; i < N / 8; i++) {
            p->coeffs[8 * i] = (int32_t)(buf[3 * i] & 0x07);
            p->coeffs[8 * i + 1] = (int32_t)((buf[3 * i] >> 3) & 0x07);
            p->coeffs[8 * i + 2] = (int32_t)(((buf[3 * i] >> 6) | (buf[3 * i + 1] << 2)) & 0x07);
            p->coeffs[8 * i + 3] = (int32_t)((buf[3 * i + 1] >> 1) & 0x07);
            p->coeffs[8 * i + 4] = (int32_t)((buf[3 * i + 1] >> 4) & 0x07);
            p->coeffs[8 * i + 5] =
                (int32_t)(((buf[3 * i + 1] >> 7) | (buf[3 * i + 2] << 1)) & 0x07);
            p->coeffs[8 * i + 6] = (int32_t)((buf[3 * i + 2] >> 2) & 0x07);
            p->coeffs[8 * i + 7] = (int32_t)((buf[3 * i + 2] >> 5) & 0x07);

            {
                unsigned int j;
                for (j = 0; j < 8; j++) {
                    p->coeffs[8 * i + j] = eta - p->coeffs[8 * i + j];
                }
            }
        }
    } else {
        for (i = 0; i < N / 2; i++) {
            p->coeffs[2 * i] = (int32_t)(eta - (buf[i] & 0x0F));
            p->coeffs[2 * i + 1] = (int32_t)(eta - (buf[i] >> 4));
        }
    }
}

/**
 * @brief Pack a gamma1-bounded polynomial into bytes.
 *
 * Coefficients are shifted by gamma1 before packing.
 */
static void dsa_poly_pack_z(uint8_t *buf, const dsa_poly_t *p, int32_t gamma1) {
    unsigned int i;
    uint32_t t[4];

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < N / 4; i++) {
            t[0] = (uint32_t)(gamma1 - p->coeffs[4 * i]);
            t[1] = (uint32_t)(gamma1 - p->coeffs[4 * i + 1]);
            t[2] = (uint32_t)(gamma1 - p->coeffs[4 * i + 2]);
            t[3] = (uint32_t)(gamma1 - p->coeffs[4 * i + 3]);

            buf[9 * i] = (uint8_t)(t[0]);
            buf[9 * i + 1] = (uint8_t)(t[0] >> 8);
            buf[9 * i + 2] = (uint8_t)((t[0] >> 16) | (t[1] << 2));
            buf[9 * i + 3] = (uint8_t)(t[1] >> 6);
            buf[9 * i + 4] = (uint8_t)((t[1] >> 14) | (t[2] << 4));
            buf[9 * i + 5] = (uint8_t)(t[2] >> 4);
            buf[9 * i + 6] = (uint8_t)((t[2] >> 12) | (t[3] << 6));
            buf[9 * i + 7] = (uint8_t)(t[3] >> 2);
            buf[9 * i + 8] = (uint8_t)(t[3] >> 10);
        }
    } else {
        /* gamma1 = 2^19 */
        for (i = 0; i < N / 2; i++) {
            t[0] = (uint32_t)(gamma1 - p->coeffs[2 * i]);
            t[1] = (uint32_t)(gamma1 - p->coeffs[2 * i + 1]);

            buf[5 * i] = (uint8_t)(t[0]);
            buf[5 * i + 1] = (uint8_t)(t[0] >> 8);
            buf[5 * i + 2] = (uint8_t)((t[0] >> 16) | (t[1] << 4));
            buf[5 * i + 3] = (uint8_t)(t[1] >> 4);
            buf[5 * i + 4] = (uint8_t)(t[1] >> 12);
        }
    }
}

/**
 * @brief Unpack a z polynomial from bytes.
 */
static void dsa_poly_unpack_z(dsa_poly_t *p, const uint8_t *buf, int32_t gamma1) {
    unsigned int i;

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < N / 4; i++) {
            p->coeffs[4 * i] = (int32_t)(((uint32_t)buf[9 * i] | ((uint32_t)buf[9 * i + 1] << 8) |
                                          ((uint32_t)buf[9 * i + 2] << 16)) &
                                         0x3FFFF);
            p->coeffs[4 * i + 1] =
                (int32_t)((((uint32_t)buf[9 * i + 2] >> 2) | ((uint32_t)buf[9 * i + 3] << 6) |
                           ((uint32_t)buf[9 * i + 4] << 14)) &
                          0x3FFFF);
            p->coeffs[4 * i + 2] =
                (int32_t)((((uint32_t)buf[9 * i + 4] >> 4) | ((uint32_t)buf[9 * i + 5] << 4) |
                           ((uint32_t)buf[9 * i + 6] << 12)) &
                          0x3FFFF);
            p->coeffs[4 * i + 3] =
                (int32_t)((((uint32_t)buf[9 * i + 6] >> 6) | ((uint32_t)buf[9 * i + 7] << 2) |
                           ((uint32_t)buf[9 * i + 8] << 10)) &
                          0x3FFFF);

            {
                unsigned int j;
                for (j = 0; j < 4; j++) {
                    p->coeffs[4 * i + j] = gamma1 - p->coeffs[4 * i + j];
                }
            }
        }
    } else {
        for (i = 0; i < N / 2; i++) {
            p->coeffs[2 * i] = (int32_t)(((uint32_t)buf[5 * i] | ((uint32_t)buf[5 * i + 1] << 8) |
                                          ((uint32_t)buf[5 * i + 2] << 16)) &
                                         0xFFFFF);
            p->coeffs[2 * i + 1] =
                (int32_t)((((uint32_t)buf[5 * i + 2] >> 4) | ((uint32_t)buf[5 * i + 3] << 4) |
                           ((uint32_t)buf[5 * i + 4] << 12)) &
                          0xFFFFF);

            p->coeffs[2 * i] = gamma1 - p->coeffs[2 * i];
            p->coeffs[2 * i + 1] = gamma1 - p->coeffs[2 * i + 1];
        }
    }
}

/**
 * @brief Sample a polynomial with coefficients in [-eta, eta] from SHAKE-256.
 */
static void dsa_poly_uniform_eta(dsa_poly_t *p, const uint8_t seed[], size_t seedlen,
                                 uint16_t nonce, int eta) {
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
    while (ctr < N) {
        uint32_t t;

        if (pos >= sizeof(buf)) {
            rivide_shake_squeeze(&state, buf, sizeof(buf));
            pos = 0;
        }

        if (eta == 2) {
            t = (uint32_t)buf[pos++];
            uint32_t d1 = t & 0x0F;
            uint32_t d2 = t >> 4;
            if (d1 < 15 && ctr < N) {
                d1 = d1 - (5 * (d1 / 5)); /* d1 mod 5 */
                p->coeffs[ctr++] = (int32_t)(2 - d1);
            }
            if (d2 < 15 && ctr < N) {
                d2 = d2 - (5 * (d2 / 5));
                p->coeffs[ctr++] = (int32_t)(2 - d2);
            }
        } else {
            /* eta == 4 */
            t = (uint32_t)buf[pos++];
            uint32_t d1 = t & 0x0F;
            uint32_t d2 = t >> 4;
            if (d1 < 9 && ctr < N) {
                p->coeffs[ctr++] = (int32_t)(4 - d1);
            }
            if (d2 < 9 && ctr < N) {
                p->coeffs[ctr++] = (int32_t)(4 - d2);
            }
        }
    }

    rivide_cleanse(buf, sizeof(buf));
}

/**
 * @brief Sample a uniformly random polynomial from SHAKE-128 (ExpandA).
 *
 * Uses rejection sampling to produce coefficients in [0, q-1].
 */
static void dsa_poly_uniform(dsa_poly_t *p, const uint8_t seed[32], uint16_t nonce) {
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
    while (ctr < N) {
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

        if (t < (uint32_t)Q) {
            p->coeffs[ctr++] = (int32_t)t;
        }
    }
}

/**
 * @brief Sample a masking polynomial with coefficients in [-gamma1+1, gamma1].
 */
static void dsa_poly_uniform_gamma1(dsa_poly_t *p, const uint8_t seed[], size_t seedlen,
                                    uint16_t nonce, int32_t gamma1) {
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
 * and the rest zero, using SHAKE-256 output for sampling.
 *
 * @param[out] c     Challenge polynomial.
 * @param[in]  seed  Challenge seed (c_tilde).
 * @param[in]  len   Length of seed in bytes.
 * @param[in]  tau   Number of non-zero coefficients.
 */
static void dsa_poly_challenge(dsa_poly_t *c, const uint8_t *seed, size_t len, unsigned int tau) {
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

    for (i = 0; i < N; i++) {
        c->coeffs[i] = 0;
    }

    pos = 8;
    for (i = N - tau; i < N; i++) {
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
 * @param[out] t     Result vector (k polynomials).
 * @param[in]  rho   32-byte seed for ExpandA.
 * @param[in]  s     Input vector (l polynomials, NTT domain).
 * @param[in]  k     Number of rows.
 * @param[in]  l     Number of columns.
 */
static void dsa_expand_matrix_mul(dsa_polyveck_t *t, const uint8_t rho[32], const dsa_polyvecl_t *s,
                                  int k, int l) {
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
                for (idx = 0; idx < N; idx++) {
                    t->vec[i].coeffs[idx] = tmp.coeffs[idx];
                }
            } else {
                dsa_poly_add(&t->vec[i], &t->vec[i], &tmp);
            }
        }
        dsa_poly_reduce(&t->vec[i]);
    }
}

/**
 * @brief Pack the public key: rho || t1.
 */
static void dsa_pack_pk(uint8_t *pk, const uint8_t rho[32], const dsa_polyveck_t *t1, int k) {
    unsigned int i;
    for (i = 0; i < 32; i++) {
        pk[i] = rho[i];
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_pack_t1(pk + 32 + 320 * i, &t1->vec[i]);
    }
}

/**
 * @brief Unpack the public key.
 */
static void dsa_unpack_pk(uint8_t rho[32], dsa_polyveck_t *t1, const uint8_t *pk, int k) {
    unsigned int i;
    for (i = 0; i < 32; i++) {
        rho[i] = pk[i];
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_unpack_t1(&t1->vec[i], pk + 32 + 320 * i);
    }
}

/**
 * @brief Pack the secret key: rho || K || tr || s1 || s2 || t0.
 */
static void dsa_pack_sk(uint8_t *sk, const uint8_t rho[32], const uint8_t tr[64],
                        const uint8_t K[32], const dsa_polyvecl_t *s1, const dsa_polyveck_t *s2,
                        const dsa_polyveck_t *t0, int k, int l, int eta) {
    unsigned int i;
    size_t offset = 0;
    size_t eta_bytes = (eta == 2) ? 96 : 128; /* per polynomial */

    for (i = 0; i < 32; i++)
        sk[offset++] = rho[i];
    for (i = 0; i < 32; i++)
        sk[offset++] = K[i];
    for (i = 0; i < 64; i++)
        sk[offset++] = tr[i];

    for (i = 0; i < (unsigned int)l; i++) {
        dsa_poly_pack_eta(sk + offset, &s1->vec[i], eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_pack_eta(sk + offset, &s2->vec[i], eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        /* t0 packing: coefficients in [-(2^12), 2^12], packed as 13 bits
         * each, 8 coefficients per 13 bytes (416 bytes per polynomial). */
        unsigned int j;
        for (j = 0; j < N / 8; j++) {
            uint32_t t[8];
            unsigned int m;
            for (m = 0; m < 8; m++) {
                t[m] = (uint32_t)((1 << (D_BITS - 1)) - t0->vec[i].coeffs[8 * j + m]);
            }
            sk[offset + 13 * j + 0] = (uint8_t)(t[0]);
            sk[offset + 13 * j + 1] = (uint8_t)(t[0] >> 8);
            sk[offset + 13 * j + 1] |= (uint8_t)(t[1] << 5);
            sk[offset + 13 * j + 2] = (uint8_t)(t[1] >> 3);
            sk[offset + 13 * j + 3] = (uint8_t)(t[1] >> 11);
            sk[offset + 13 * j + 3] |= (uint8_t)(t[2] << 2);
            sk[offset + 13 * j + 4] = (uint8_t)(t[2] >> 6);
            sk[offset + 13 * j + 4] |= (uint8_t)(t[3] << 7);
            sk[offset + 13 * j + 5] = (uint8_t)(t[3] >> 1);
            sk[offset + 13 * j + 6] = (uint8_t)(t[3] >> 9);
            sk[offset + 13 * j + 6] |= (uint8_t)(t[4] << 4);
            sk[offset + 13 * j + 7] = (uint8_t)(t[4] >> 4);
            sk[offset + 13 * j + 8] = (uint8_t)(t[4] >> 12);
            sk[offset + 13 * j + 8] |= (uint8_t)(t[5] << 1);
            sk[offset + 13 * j + 9] = (uint8_t)(t[5] >> 7);
            sk[offset + 13 * j + 9] |= (uint8_t)(t[6] << 6);
            sk[offset + 13 * j + 10] = (uint8_t)(t[6] >> 2);
            sk[offset + 13 * j + 11] = (uint8_t)(t[6] >> 10);
            sk[offset + 13 * j + 11] |= (uint8_t)(t[7] << 3);
            sk[offset + 13 * j + 12] = (uint8_t)(t[7] >> 5);
        }
        offset += 416;
    }
}

/**
 * @brief Unpack the secret key.
 */
static void dsa_unpack_sk(uint8_t rho[32], uint8_t tr[64], uint8_t K[32], dsa_polyvecl_t *s1,
                          dsa_polyveck_t *s2, dsa_polyveck_t *t0, const uint8_t *sk, int k, int l,
                          int eta) {
    unsigned int i;
    size_t offset = 0;
    size_t eta_bytes = (eta == 2) ? 96 : 128;

    for (i = 0; i < 32; i++)
        rho[i] = sk[offset++];
    for (i = 0; i < 32; i++)
        K[i] = sk[offset++];
    for (i = 0; i < 64; i++)
        tr[i] = sk[offset++];

    for (i = 0; i < (unsigned int)l; i++) {
        dsa_poly_unpack_eta(&s1->vec[i], sk + offset, eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_unpack_eta(&s2->vec[i], sk + offset, eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        unsigned int j;
        for (j = 0; j < N / 8; j++) {
            const uint8_t *a = sk + offset + 13 * j;
            uint32_t t0v = (uint32_t)a[0] | ((uint32_t)a[1] << 8);
            uint32_t t1v = ((uint32_t)a[1] >> 5) | ((uint32_t)a[2] << 3) | ((uint32_t)a[3] << 11);
            uint32_t t2v = ((uint32_t)a[3] >> 2) | ((uint32_t)a[4] << 6);
            uint32_t t3v = ((uint32_t)a[4] >> 7) | ((uint32_t)a[5] << 1) | ((uint32_t)a[6] << 9);
            uint32_t t4v = ((uint32_t)a[6] >> 4) | ((uint32_t)a[7] << 4) | ((uint32_t)a[8] << 12);
            uint32_t t5v = ((uint32_t)a[8] >> 1) | ((uint32_t)a[9] << 7);
            uint32_t t6v = ((uint32_t)a[9] >> 6) | ((uint32_t)a[10] << 2) | ((uint32_t)a[11] << 10);
            uint32_t t7v = ((uint32_t)a[11] >> 3) | ((uint32_t)a[12] << 5);
            t0->vec[i].coeffs[8 * j + 0] = (int32_t)((1 << (D_BITS - 1)) - (t0v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 1] = (int32_t)((1 << (D_BITS - 1)) - (t1v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 2] = (int32_t)((1 << (D_BITS - 1)) - (t2v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 3] = (int32_t)((1 << (D_BITS - 1)) - (t3v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 4] = (int32_t)((1 << (D_BITS - 1)) - (t4v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 5] = (int32_t)((1 << (D_BITS - 1)) - (t5v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 6] = (int32_t)((1 << (D_BITS - 1)) - (t6v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 7] = (int32_t)((1 << (D_BITS - 1)) - (t7v & 0x1FFF));
        }
        offset += 416;
    }
}

/**
 * @brief Pack hint vector into signature bytes.
 */
static size_t dsa_pack_hint(uint8_t *buf, const dsa_polyveck_t *h, int k, int omega) {
    unsigned int i, j;
    size_t idx = 0;

    for (i = 0; i < (unsigned int)omega + (unsigned int)k; i++) {
        buf[i] = 0;
    }

    idx = 0;
    for (i = 0; i < (unsigned int)k; i++) {
        for (j = 0; j < N; j++) {
            if (h->vec[i].coeffs[j] != 0) {
                buf[idx++] = (uint8_t)j;
            }
        }
        buf[(unsigned int)omega + i] = (uint8_t)idx;
    }

    return (size_t)omega + (size_t)k;
}

/**
 * @brief Unpack hint vector from signature bytes.
 *
 * @return 0 on success, 1 if the hint encoding is invalid.
 */
static int dsa_unpack_hint(dsa_polyveck_t *h, const uint8_t *buf, int k, int omega) {
    unsigned int i, j, prev;

    for (i = 0; i < (unsigned int)k; i++) {
        for (j = 0; j < N; j++) {
            h->vec[i].coeffs[j] = 0;
        }
    }

    prev = 0;
    for (i = 0; i < (unsigned int)k; i++) {
        unsigned int end = (unsigned int)buf[(unsigned int)omega + i];
        if (end < prev || end > (unsigned int)omega) {
            return 1;
        }
        for (j = prev; j < end; j++) {
            if (j > prev && buf[j] <= buf[j - 1]) {
                return 1;
            }
            h->vec[i].coeffs[(unsigned int)buf[j]] = 1;
        }
        prev = end;
    }

    /* Remaining entries in buf must be zero. */
    for (j = prev; j < (unsigned int)omega; j++) {
        if (buf[j] != 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Internal ML-DSA key generation.
 */
static rivide_status_t ml_dsa_keygen_internal(uint8_t *pk, uint8_t *sk, int k, int l, int eta,
                                              int32_t gamma2) {
    uint8_t seed[32], buf[128];
    uint8_t rho[32], rho_prime[64], K[32];
    dsa_polyvecl_t s1, s1_hat;
    dsa_polyveck_t s2, t, t1, t0;
    uint8_t tr[64];
    rivide_status_t ret;
    int i;

    (void)gamma2;

    ret = rivide_randombytes(seed, 32);
    if (ret != RIVIDE_SUCCESS)
        return ret;

    /* H(seed || k || l) -> rho, rho', K */
    {
        uint8_t h_input[34];
        unsigned int j;
        for (j = 0; j < 32; j++)
            h_input[j] = seed[j];
        h_input[32] = (uint8_t)k;
        h_input[33] = (uint8_t)l;
        rivide_shake256(buf, 128, h_input, 34);
    }

    for (i = 0; i < 32; i++)
        rho[i] = buf[i];
    for (i = 0; i < 64; i++)
        rho_prime[i] = buf[32 + i];
    for (i = 0; i < 32; i++)
        K[i] = buf[96 + i];

    /* ExpandS: sample s1, s2. */
    for (i = 0; i < l; i++) {
        dsa_poly_uniform_eta(&s1.vec[i], rho_prime, 64, (uint16_t)i, eta);
    }
    for (i = 0; i < k; i++) {
        dsa_poly_uniform_eta(&s2.vec[i], rho_prime, 64, (uint16_t)(l + i), eta);
    }

    /* s1_hat = NTT(s1) */
    for (i = 0; i < l; i++) {
        unsigned int j;
        for (j = 0; j < N; j++) {
            s1_hat.vec[i].coeffs[j] = s1.vec[i].coeffs[j];
        }
        dsa_poly_ntt(&s1_hat.vec[i]);
    }

    /* t = A * s1_hat (in NTT domain) */
    dsa_expand_matrix_mul(&t, rho, &s1_hat, k, l);

    /* t = INTT(t) + s2 */
    for (i = 0; i < k; i++) {
        dsa_poly_invntt(&t.vec[i]);
        dsa_poly_add(&t.vec[i], &t.vec[i], &s2.vec[i]);
        dsa_poly_caddq(&t.vec[i]);
    }

    /* Power2Round(t) -> (t1, t0) */
    for (i = 0; i < k; i++) {
        unsigned int j;
        for (j = 0; j < N; j++) {
            t1.vec[i].coeffs[j] = power2round(t.vec[i].coeffs[j], &t0.vec[i].coeffs[j]);
        }
    }

    /* Pack public key. */
    dsa_pack_pk(pk, rho, &t1, k);

    /* tr = H(pk) */
    {
        size_t pk_bytes = 32 + 320 * (size_t)k;
        rivide_shake256(tr, 64, pk, pk_bytes);
    }

    /* Pack secret key. */
    dsa_pack_sk(sk, rho, tr, K, &s1, &s2, &t0, k, l, eta);

    /* Cleanse. */
    rivide_cleanse(seed, sizeof(seed));
    rivide_cleanse(buf, sizeof(buf));
    rivide_cleanse(rho_prime, sizeof(rho_prime));
    rivide_cleanse(K, sizeof(K));
    rivide_cleanse(&s1, sizeof(s1));
    rivide_cleanse(&s1_hat, sizeof(s1_hat));
    rivide_cleanse(&s2, sizeof(s2));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Internal ML-DSA signing with rejection sampling.
 */
static rivide_status_t ml_dsa_sign_internal(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                            size_t msglen, const uint8_t *sk, int k, int l, int eta,
                                            int32_t gamma1, int32_t gamma2, unsigned int tau,
                                            int omega, size_t ctilde_bytes) {
    uint8_t rho[32], tr[64], K[32];
    dsa_polyvecl_t s1, y, z;
    dsa_polyveck_t s2, t0, w, w0, w1;
    dsa_polyveck_t cs2, ct0, h;
    dsa_poly_t cp;
    uint8_t mu[64];
    uint8_t rho_prime[64];
    int i, reject;
    unsigned int hint_count;
    uint16_t nonce = 0;
    size_t sig_offset;
    size_t z_bytes_per_poly;

    if (!sig || !siglen || !msg || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* Unpack secret key. */
    dsa_unpack_sk(rho, tr, K, &s1, &s2, &t0, sk, k, l, eta);

    /* NTT(s1), NTT(s2), NTT(t0). */
    for (i = 0; i < l; i++) {
        dsa_poly_ntt(&s1.vec[i]);
    }
    for (i = 0; i < k; i++) {
        dsa_poly_ntt(&s2.vec[i]);
    }
    for (i = 0; i < k; i++) {
        dsa_poly_ntt(&t0.vec[i]);
    }

    /* mu = CRH(tr || pre || msg), with pre = (0x00, ctxlen=0x00) for the
     * empty-context API (FIPS 204 / reference convention). */
    {
        rivide_keccak_state_t hstate;
        static const uint8_t pre[2] = {0x00, 0x00};
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, tr, 64);
        rivide_shake_absorb(&hstate, pre, 2);
        rivide_shake_absorb(&hstate, msg, msglen);
        rivide_shake_squeeze(&hstate, mu, 64);
    }

    /* rho' = CRH(K || rnd || mu) for deterministic signing (rnd = 0^32). */
    {
        rivide_keccak_state_t hstate;
        uint8_t rnd[32];
        unsigned int ri;
        for (ri = 0; ri < 32; ri++) {
            rnd[ri] = 0;
        }
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, K, 32);
        rivide_shake_absorb(&hstate, rnd, 32);
        rivide_shake_absorb(&hstate, mu, 64);
        rivide_shake_squeeze(&hstate, rho_prime, 64);
    }

    /* Rejection sampling loop. */
    int loop_ctr = 0;
    do {
        reject = 0;
        loop_ctr++;
        if (loop_ctr > 10000) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
        /* Sample masking vector y from ExpandMask(rho', nonce). */
        for (i = 0; i < l; i++) {
            dsa_poly_uniform_gamma1(&y.vec[i], rho_prime, 64, (uint16_t)(nonce + (uint16_t)i),
                                    gamma1);
        }
        nonce = (uint16_t)(nonce + (uint16_t)l);

        /* w = A * NTT(y) */
        {
            dsa_polyvecl_t y_hat;
            for (i = 0; i < l; i++) {
                unsigned int j;
                for (j = 0; j < N; j++) {
                    y_hat.vec[i].coeffs[j] = y.vec[i].coeffs[j];
                }
                dsa_poly_ntt(&y_hat.vec[i]);
            }
            dsa_expand_matrix_mul(&w, rho, &y_hat, k, l);
            for (i = 0; i < k; i++) {
                dsa_poly_invntt(&w.vec[i]);
                dsa_poly_caddq(&w.vec[i]);
            }
        }
        /* Decompose w into w1 (high bits) and w0 (low bits). */
        for (i = 0; i < k; i++) {
            unsigned int j;
            for (j = 0; j < N; j++) {
                int32_t a0;
                w1.vec[i].coeffs[j] = decompose(w.vec[i].coeffs[j], &a0, gamma2);
                w0.vec[i].coeffs[j] = a0;
            }
        }
        /* Challenge: c_tilde = H(mu || w1_encode). */
        {
            rivide_keccak_state_t hstate;
            rivide_shake256_init(&hstate);
            rivide_shake_absorb(&hstate, mu, 64);

            /* Encode w1 and absorb. */
            for (i = 0; i < k; i++) {
                uint8_t w1_buf[N]; /* Sufficient for w1 encoding. */
                unsigned int j;
                size_t w1_bytes;

                if (gamma2 == (Q - 1) / 88) {
                    /* 6 bits per coefficient, 256 * 6 / 8 = 192 bytes */
                    w1_bytes = 192;
                    for (j = 0; j < N / 4; j++) {
                        w1_buf[3 * j] =
                            (uint8_t)(w1.vec[i].coeffs[4 * j] | (w1.vec[i].coeffs[4 * j + 1] << 6));
                        w1_buf[3 * j + 1] = (uint8_t)((w1.vec[i].coeffs[4 * j + 1] >> 2) |
                                                      (w1.vec[i].coeffs[4 * j + 2] << 4));
                        w1_buf[3 * j + 2] = (uint8_t)((w1.vec[i].coeffs[4 * j + 2] >> 4) |
                                                      (w1.vec[i].coeffs[4 * j + 3] << 2));
                    }
                } else {
                    /* gamma2 == (Q-1)/32: 4 bits per coeff, 128 bytes */
                    w1_bytes = 128;
                    for (j = 0; j < N / 2; j++) {
                        w1_buf[j] =
                            (uint8_t)(w1.vec[i].coeffs[2 * j] | (w1.vec[i].coeffs[2 * j + 1] << 4));
                    }
                }
                rivide_shake_absorb(&hstate, w1_buf, w1_bytes);
            }

            uint8_t ctilde[64];
            rivide_shake_squeeze(&hstate, ctilde, ctilde_bytes);

            /* c = SampleInBall(c_tilde). */
            dsa_poly_challenge(&cp, ctilde, ctilde_bytes, tau);

            /* Store c_tilde in signature. */
            for (i = 0; i < (int)ctilde_bytes; i++) {
                sig[i] = ctilde[i];
            }
        }

        /* z = y + c * s1. */
        {
            dsa_poly_t cp_hat;
            unsigned int j;
            for (j = 0; j < N; j++)
                cp_hat.coeffs[j] = cp.coeffs[j];
            dsa_poly_ntt(&cp_hat);

            for (i = 0; i < l; i++) {
                dsa_poly_pointwise(&z.vec[i], &cp_hat, &s1.vec[i]);
                dsa_poly_invntt(&z.vec[i]);
                dsa_poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
                dsa_poly_reduce(&z.vec[i]);
            }

            /* Check ||z||_inf < gamma1 - beta. */
            {
                int32_t beta = (int32_t)tau * eta;
                for (i = 0; i < l; i++) {
                    if (dsa_poly_chknorm(&z.vec[i], gamma1 - beta)) {
                        reject = 1;
                        break;
                    }
                }
            }

            if (!reject) {
                /* Compute cs2 and ct0. */
                for (i = 0; i < k; i++) {
                    dsa_poly_pointwise(&cs2.vec[i], &cp_hat, &s2.vec[i]);
                    dsa_poly_invntt(&cs2.vec[i]);
                }
                for (i = 0; i < k; i++) {
                    dsa_poly_pointwise(&ct0.vec[i], &cp_hat, &t0.vec[i]);
                    dsa_poly_invntt(&ct0.vec[i]);
                    dsa_poly_reduce(&ct0.vec[i]);
                }

                /* w0 = LowBits(w) - cs2; check ||w0||_inf < gamma2 - beta. */
                {
                    int32_t beta = (int32_t)tau * eta;
                    for (i = 0; i < k; i++) {
                        dsa_poly_sub(&w0.vec[i], &w0.vec[i], &cs2.vec[i]);
                        dsa_poly_reduce(&w0.vec[i]);
                        if (dsa_poly_chknorm(&w0.vec[i], gamma2 - beta)) {
                            reject = 1;
                            break;
                        }
                    }
                }
            }

            if (!reject) {
                /* Check ||ct0||_inf < gamma2. */
                for (i = 0; i < k; i++) {
                    if (dsa_poly_chknorm(&ct0.vec[i], gamma2)) {
                        reject = 1;
                        break;
                    }
                }
            }

            if (!reject) {
                /* h = MakeHint(LowBits(w) - cs2 + ct0, HighBits(w)); retry if too many hints. */
                hint_count = 0;
                for (i = 0; i < k; i++) {
                    unsigned int j;
                    dsa_poly_add(&w0.vec[i], &w0.vec[i], &ct0.vec[i]);
                    for (j = 0; j < N; j++) {
                        h.vec[i].coeffs[j] =
                            (int32_t)make_hint(w0.vec[i].coeffs[j], w1.vec[i].coeffs[j], gamma2);
                        hint_count += (unsigned int)h.vec[i].coeffs[j];
                    }
                }
                if (hint_count > (unsigned int)omega) {
                    reject = 1;
                }
            }
        }

    } while (reject);

    /* Pack signature: c_tilde || z || h. */
    {
        sig_offset = ctilde_bytes;

        if (gamma1 == (1 << 17)) {
            z_bytes_per_poly = 576;
        } else {
            z_bytes_per_poly = 640;
        }

        for (i = 0; i < l; i++) {
            dsa_poly_pack_z(sig + sig_offset, &z.vec[i], gamma1);
            sig_offset += z_bytes_per_poly;
        }

        sig_offset += dsa_pack_hint(sig + sig_offset, &h, k, omega);
        *siglen = sig_offset;
    }

    /* Cleanse sensitive data. */
    rivide_cleanse(&s1, sizeof(s1));
    rivide_cleanse(&s2, sizeof(s2));
    rivide_cleanse(&t0, sizeof(t0));
    rivide_cleanse(K, sizeof(K));
    rivide_cleanse(rho_prime, sizeof(rho_prime));
    rivide_cleanse(&y, sizeof(y));
    rivide_cleanse(mu, sizeof(mu));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Internal ML-DSA verification.
 */
static rivide_status_t ml_dsa_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                              size_t msglen, const uint8_t *pk, int k, int l,
                                              int32_t gamma1, int32_t gamma2, unsigned int tau,
                                              int omega, size_t ctilde_bytes) {
    uint8_t rho[32], tr[64], mu[64];
    dsa_polyveck_t t1, h, w1_prime;
    dsa_polyvecl_t z;
    dsa_poly_t cp;
    size_t sig_offset;
    size_t z_bytes_per_poly;
    int i;
    int32_t beta;

    if (!sig || !msg || !pk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    (void)siglen;

    /* Unpack public key. */
    dsa_unpack_pk(rho, &t1, pk, k);

    /* tr = H(pk). */
    {
        size_t pk_bytes = 32 + 320 * (size_t)k;
        rivide_shake256(tr, 64, pk, pk_bytes);
    }

    /* mu = CRH(tr || pre || msg), with pre = (0x00, 0x00) for the
     * empty-context API (must match the signing side). */
    {
        rivide_keccak_state_t hstate;
        static const uint8_t pre[2] = {0x00, 0x00};
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, tr, 64);
        rivide_shake_absorb(&hstate, pre, 2);
        rivide_shake_absorb(&hstate, msg, msglen);
        rivide_shake_squeeze(&hstate, mu, 64);
    }

    /* Unpack signature: c_tilde || z || h. */
    sig_offset = ctilde_bytes;

    if (gamma1 == (1 << 17)) {
        z_bytes_per_poly = 576;
    } else {
        z_bytes_per_poly = 640;
    }

    for (i = 0; i < l; i++) {
        dsa_poly_unpack_z(&z.vec[i], sig + sig_offset, gamma1);
        sig_offset += z_bytes_per_poly;
    }

    /* Check ||z||_inf < gamma1 - beta. */
    beta = (int32_t)tau * RIVIDE_ML_DSA_65_ETA; /* Use appropriate eta. */
    if (k == 8)
        beta = (int32_t)tau * RIVIDE_ML_DSA_87_ETA;
    for (i = 0; i < l; i++) {
        if (dsa_poly_chknorm(&z.vec[i], gamma1 - beta)) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
    }

    /* Unpack hints. */
    if (dsa_unpack_hint(&h, sig + sig_offset, k, omega)) {
        return RIVIDE_ERR_VERIFICATION_FAILED;
    }

    /* c = SampleInBall(c_tilde). */
    dsa_poly_challenge(&cp, sig, ctilde_bytes, tau);

    /* Compute w1' = UseHint(h, A*NTT(z) - c*NTT(t1*2^d)). */
    {
        dsa_polyvecl_t z_hat;
        dsa_poly_t cp_hat;
        unsigned int j;

        /* NTT(z). */
        for (i = 0; i < l; i++) {
            for (j = 0; j < N; j++)
                z_hat.vec[i].coeffs[j] = z.vec[i].coeffs[j];
            dsa_poly_ntt(&z_hat.vec[i]);
        }

        /* NTT(c). */
        for (j = 0; j < N; j++)
            cp_hat.coeffs[j] = cp.coeffs[j];
        dsa_poly_ntt(&cp_hat);

        /* A * z_hat. */
        dsa_expand_matrix_mul(&w1_prime, rho, &z_hat, k, l);
        for (i = 0; i < k; i++) {
            dsa_poly_invntt(&w1_prime.vec[i]);
        }

        /* Subtract c * t1 * 2^d. */
        for (i = 0; i < k; i++) {
            dsa_poly_t ct1;
            /* t1 * 2^d in NTT domain. */
            dsa_poly_t t1_shifted;
            for (j = 0; j < N; j++) {
                t1_shifted.coeffs[j] = t1.vec[i].coeffs[j] << D_BITS;
            }
            dsa_poly_ntt(&t1_shifted);
            dsa_poly_pointwise(&ct1, &cp_hat, &t1_shifted);
            dsa_poly_invntt(&ct1);

            dsa_poly_sub(&w1_prime.vec[i], &w1_prime.vec[i], &ct1);
            dsa_poly_caddq(&w1_prime.vec[i]);

            /* UseHint. */
            for (j = 0; j < N; j++) {
                w1_prime.vec[i].coeffs[j] =
                    use_hint(w1_prime.vec[i].coeffs[j], (unsigned int)h.vec[i].coeffs[j], gamma2);
            }
        }
    }

    /* Recompute c_tilde' = H(mu || w1_encode) and compare. */
    {
        rivide_keccak_state_t hstate;
        uint8_t ctilde_prime[64];

        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, mu, 64);

        for (i = 0; i < k; i++) {
            uint8_t w1_buf[N];
            unsigned int j;
            size_t w1_bytes;

            if (gamma2 == (Q - 1) / 88) {
                w1_bytes = 192;
                for (j = 0; j < N / 4; j++) {
                    w1_buf[3 * j] = (uint8_t)(w1_prime.vec[i].coeffs[4 * j] |
                                              (w1_prime.vec[i].coeffs[4 * j + 1] << 6));
                    w1_buf[3 * j + 1] = (uint8_t)((w1_prime.vec[i].coeffs[4 * j + 1] >> 2) |
                                                  (w1_prime.vec[i].coeffs[4 * j + 2] << 4));
                    w1_buf[3 * j + 2] = (uint8_t)((w1_prime.vec[i].coeffs[4 * j + 2] >> 4) |
                                                  (w1_prime.vec[i].coeffs[4 * j + 3] << 2));
                }
            } else {
                w1_bytes = 128;
                for (j = 0; j < N / 2; j++) {
                    w1_buf[j] = (uint8_t)(w1_prime.vec[i].coeffs[2 * j] |
                                          (w1_prime.vec[i].coeffs[2 * j + 1] << 4));
                }
            }
            rivide_shake_absorb(&hstate, w1_buf, w1_bytes);
        }

        rivide_shake_squeeze(&hstate, ctilde_prime, ctilde_bytes);

        if (rivide_ct_memcmp(sig, ctilde_prime, ctilde_bytes) != 0) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
    }

    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk)
        return RIVIDE_ERR_NULL_PTR;
    return ml_dsa_keygen_internal(pk, sk, RIVIDE_ML_DSA_65_K, RIVIDE_ML_DSA_65_L,
                                  RIVIDE_ML_DSA_65_ETA, RIVIDE_ML_DSA_65_GAMMA2);
}

rivide_status_t rivide_ml_dsa_65_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk) {
    return ml_dsa_sign_internal(sig, siglen, msg, msglen, sk, RIVIDE_ML_DSA_65_K,
                                RIVIDE_ML_DSA_65_L, RIVIDE_ML_DSA_65_ETA, RIVIDE_ML_DSA_65_GAMMA1,
                                RIVIDE_ML_DSA_65_GAMMA2, RIVIDE_ML_DSA_TAU_65,
                                RIVIDE_ML_DSA_65_OMEGA, RIVIDE_ML_DSA_65_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_65_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk) {
    (void)siglen;
    return ml_dsa_verify_internal(sig, siglen, msg, msglen, pk, RIVIDE_ML_DSA_65_K,
                                  RIVIDE_ML_DSA_65_L, RIVIDE_ML_DSA_65_GAMMA1,
                                  RIVIDE_ML_DSA_65_GAMMA2, RIVIDE_ML_DSA_TAU_65,
                                  RIVIDE_ML_DSA_65_OMEGA, RIVIDE_ML_DSA_65_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_87_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk)
        return RIVIDE_ERR_NULL_PTR;
    return ml_dsa_keygen_internal(pk, sk, RIVIDE_ML_DSA_87_K, RIVIDE_ML_DSA_87_L,
                                  RIVIDE_ML_DSA_87_ETA, RIVIDE_ML_DSA_87_GAMMA2);
}

rivide_status_t rivide_ml_dsa_87_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk) {
    return ml_dsa_sign_internal(sig, siglen, msg, msglen, sk, RIVIDE_ML_DSA_87_K,
                                RIVIDE_ML_DSA_87_L, RIVIDE_ML_DSA_87_ETA, RIVIDE_ML_DSA_87_GAMMA1,
                                RIVIDE_ML_DSA_87_GAMMA2, RIVIDE_ML_DSA_TAU_87,
                                RIVIDE_ML_DSA_87_OMEGA, RIVIDE_ML_DSA_87_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_87_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk) {
    (void)siglen;
    return ml_dsa_verify_internal(sig, siglen, msg, msglen, pk, RIVIDE_ML_DSA_87_K,
                                  RIVIDE_ML_DSA_87_L, RIVIDE_ML_DSA_87_GAMMA1,
                                  RIVIDE_ML_DSA_87_GAMMA2, RIVIDE_ML_DSA_TAU_87,
                                  RIVIDE_ML_DSA_87_OMEGA, RIVIDE_ML_DSA_87_CTILDEBYTES);
}
