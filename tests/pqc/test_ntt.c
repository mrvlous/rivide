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
 * @file test_ntt.c
 * @brief Unit tests for SIMD vector polynomial operations, NTT invertibility, and modular
 * reductions.
 */

#include "rivide/internal/dsa_ntt.h"
#include "rivide/internal/dsa_packing.h"
#include "rivide/internal/dsa_poly.h"
#include "rivide/internal/dsa_reduce.h"
#include "rivide/internal/dsa_rounding.h"
#include "rivide/internal/dsa_sampling.h"
#include "rivide/internal/kem_cbd.h"
#include "rivide/internal/kem_compress.h"
#include "rivide/internal/kem_encode.h"
#include "rivide/internal/kem_ntt.h"
#include "rivide/internal/kem_packing.h"
#include "rivide/internal/kem_poly.h"
#include "rivide/internal/kem_reduce.h"
#include "rivide/pqc/ntt_simd.h"

#include "test_harness.h"

int test_simd_poly_add_reduce(void) {
    int16_t a[256], b[256], r[256];
    size_t i;

    for (i = 0; i < 256; i++) {
        a[i] = (int16_t)(i * 3);
        b[i] = (int16_t)(i * 7);
    }

    rivide_simd_poly_add_reduce(r, a, b, 3329);

    /* NULL pointer validation: must be safe no-op */
    rivide_simd_poly_add_reduce(NULL, a, b, 3329);
    rivide_simd_poly_add_reduce(r, NULL, b, 3329);
    rivide_simd_poly_add_reduce(r, a, NULL, 3329);

    for (i = 0; i < 256; i++) {
        int16_t expected = (int16_t)(a[i] + b[i]);
        ASSERT_EQ(r[i], expected);
    }

    return 0;
}

int test_simd_poly_sub_reduce(void) {
    int16_t a[256], b[256], r[256];
    size_t i;

    for (i = 0; i < 256; i++) {
        a[i] = (int16_t)(i * 10);
        b[i] = (int16_t)(i * 3);
    }

    rivide_simd_poly_sub_reduce(r, a, b, 3329);

    /* NULL pointer validation: must be safe no-op */
    rivide_simd_poly_sub_reduce(NULL, a, b, 3329);
    rivide_simd_poly_sub_reduce(r, NULL, b, 3329);
    rivide_simd_poly_sub_reduce(r, a, NULL, 3329);

    for (i = 0; i < 256; i++) {
        int16_t expected = (int16_t)(a[i] - b[i]);
        ASSERT_EQ(r[i], expected);
    }

    return 0;
}

int test_ml_kem_ntt_invertibility(void) {
    poly_t p, orig;
    int trial;

    for (trial = 0; trial < 10; trial++) {
        int i;
        for (i = 0; i < 256; i++) {
            orig.coeffs[i] = (int16_t)((i * 37 + trial * 101) % 3329);
            p.coeffs[i] = orig.coeffs[i];
        }

        poly_ntt(&p);
        poly_invntt(&p);

        /* poly_invntt(poly_ntt(p)) returns p * R mod q per FIPS 203.
         * Montgomery reduce removes the Montgomery factor R = 2^16. */
        for (i = 0; i < 256; i++) {
            int16_t c = montgomery_reduce((int32_t)p.coeffs[i]);
            c = barrett_reduce(c);
            c = cond_sub_q(c);
            ASSERT_EQ(c, orig.coeffs[i]);
        }
    }

    return 0;
}

int test_ml_dsa_ntt_invertibility(void) {
    dsa_poly_t p, orig;
    int trial;

    for (trial = 0; trial < 10; trial++) {
        int i;
        for (i = 0; i < DSA_N; i++) {
            orig.coeffs[i] = (int32_t)((i * 104729 + trial * 8380417) % DSA_Q);
            if (orig.coeffs[i] < 0) {
                orig.coeffs[i] += DSA_Q;
            }
            p.coeffs[i] = orig.coeffs[i];
        }

        dsa_poly_ntt(&p);
        dsa_poly_invntt(&p);

        /* dsa_poly_invntt(dsa_poly_ntt(p)) returns p * R mod q per FIPS 204.
         * Montgomery reduction removes the Montgomery factor R = 2^32. */
        for (i = 0; i < DSA_N; i++) {
            int32_t c = dsa_montgomery_reduce((int64_t)p.coeffs[i]);
            c = dsa_caddq(dsa_reduce32(c));
            ASSERT_EQ(c, orig.coeffs[i]);
        }
    }

    return 0;
}

int test_modular_reductions(void) {
    /* Test Barrett reduction mod 3329. */
    int16_t val = 3329 + 150;
    int16_t reduced = barrett_reduce(val);
    reduced = cond_sub_q(reduced);
    ASSERT_EQ(reduced, 150);

    /* Test Dilithium caddq. */
    int32_t neg = -100;
    int32_t normalized = dsa_caddq(neg);
    ASSERT_EQ(normalized, DSA_Q - 100);

    return 0;
}

int test_simd_poly_pointwise_montgomery(void) {
    int16_t a[256], b[256], r[256];
    size_t i;

    for (i = 0; i < 256; i++) {
        a[i] = (int16_t)((i * 17) % 3329);
        b[i] = (int16_t)((i * 23) % 3329);
    }

    rivide_simd_poly_pointwise_montgomery(r, a, b, 3329, 62209);

    /* NULL pointer validation: must safely return without crash */
    rivide_simd_poly_pointwise_montgomery(NULL, a, b, 3329, 62209);
    rivide_simd_poly_pointwise_montgomery(r, NULL, b, 3329, 62209);
    rivide_simd_poly_pointwise_montgomery(r, a, NULL, 3329, 62209);

    for (i = 0; i < 256; i++) {
        int32_t prod = (int32_t)a[i] * (int32_t)b[i];
        int16_t expected = montgomery_reduce(prod);
        ASSERT_EQ(r[i], expected);
    }

    return 0;
}

int test_pqc_internal_defensive_bounds(void) {
    poly_t p = {0}, a = {0}, b = {0};
    polyvec_t v = {0};
    dsa_poly_t dp = {0}, da = {0}, db = {0};
    dsa_polyveck_t h = {0};
    uint8_t buf[1024] = {0};

    /* NULL pointer validation for internal routines */
    poly_add(NULL, &a, &b);
    poly_add(&p, NULL, &b);
    poly_add(&p, &a, NULL);

    poly_sub(NULL, &a, &b);
    poly_sub(&p, NULL, &b);
    poly_sub(&p, &a, NULL);

    poly_reduce(NULL);
    poly_tomont(NULL);
    poly_csubq(NULL);

    polyvec_ntt(NULL, 3);
    polyvec_ntt(&v, 0);
    polyvec_ntt(&v, 5);

    polyvec_pointwise_acc(NULL, &v, &v, 3);
    polyvec_pointwise_acc(&p, NULL, &v, 3);
    polyvec_pointwise_acc(&p, &v, NULL, 3);
    polyvec_pointwise_acc(&p, &v, &v, 0);
    polyvec_pointwise_acc(&p, &v, &v, 5);

    /* Type check boundary */
    ASSERT_EQ(polyvec_frombytes_check(NULL, buf, 3), -1);
    ASSERT_EQ(polyvec_frombytes_check(&v, NULL, 3), -1);
    ASSERT_EQ(polyvec_frombytes_check(&v, buf, 0), -1);
    ASSERT_EQ(polyvec_frombytes_check(&v, buf, 5), -1);

    /* CBD invalid eta */
    poly_cbd(&p, buf, 1);
    poly_cbd(&p, buf, 5);
    poly_cbd(NULL, buf, 2);
    poly_cbd(&p, NULL, 2);

    /* Dilithium poly defensive checks */
    dsa_poly_add(NULL, &da, &db);
    dsa_poly_sub(NULL, &da, &db);
    dsa_poly_reduce(NULL);
    dsa_poly_caddq(NULL);
    ASSERT_EQ(dsa_poly_chknorm(NULL, 100), 1);
    ASSERT_EQ(dsa_poly_chknorm(&dp, -1), 1);

    /* Compression & decompression bounds checks */
    ASSERT_EQ(compress_coeff(100, 0), 0);
    ASSERT_EQ(compress_coeff(100, 16), 0);
    ASSERT_EQ(compress_coeff(100, -1), 0);
    ASSERT_EQ(decompress_coeff(100, 0), 0);
    ASSERT_EQ(decompress_coeff(100, 16), 0);
    ASSERT_EQ(decompress_coeff(100, -1), 0);

    poly_compress(NULL, &p, 10);
    poly_compress(buf, NULL, 10);
    poly_compress(buf, &p, 0);
    poly_compress(buf, &p, 12);

    poly_decompress(NULL, buf, 10);
    poly_decompress(&p, NULL, 10);
    poly_decompress(&p, buf, 0);
    poly_decompress(&p, buf, 12);

    polyvec_compress(NULL, &v, 3, 10);
    polyvec_compress(buf, NULL, 3, 10);
    polyvec_compress(buf, &v, 0, 10);
    polyvec_compress(buf, &v, 5, 10);
    polyvec_compress(buf, &v, 3, 0);
    polyvec_compress(buf, &v, 3, 12);

    polyvec_decompress(NULL, buf, 3, 10);
    polyvec_decompress(&v, NULL, 3, 10);
    polyvec_decompress(&v, buf, 0, 10);
    polyvec_decompress(&v, buf, 5, 10);
    polyvec_decompress(&v, buf, 3, 0);
    polyvec_decompress(&v, buf, 3, 12);

    /* Dilithium rounding null pointer checks and parameter guards */
    {
        int32_t a0_val = 0;
        ASSERT_EQ(dsa_power2round(100, NULL), 0);
        ASSERT_EQ(dsa_decompose(100, NULL, (DSA_Q - 1) / 32), 0);
        ASSERT_EQ(dsa_decompose(100, &a0_val, 0), 0);
        ASSERT_EQ(dsa_decompose(100, &a0_val, 1000), 0);
        ASSERT_EQ(dsa_make_hint(100, 100, 0), 0);
        ASSERT_EQ(dsa_use_hint(100, 2, (DSA_Q - 1) / 32), 0);
        ASSERT_EQ(dsa_use_hint(100, 0, 0), 0);
    }

    /* Dilithium unpack hint checks */
    ASSERT_EQ(dsa_unpack_hint(NULL, buf, 6, 55), 1);
    ASSERT_EQ(dsa_unpack_hint(&h, NULL, 6, 55), 1);
    ASSERT_EQ(dsa_unpack_hint(&h, buf, 0, 55), 1);
    ASSERT_EQ(dsa_unpack_hint(&h, buf, 9, 55), 1);
    ASSERT_EQ(dsa_unpack_hint(&h, buf, 6, 0), 1);

    /* NTT & INTT NULL checks */
    poly_ntt(NULL);
    poly_invntt(NULL);
    poly_basemul(NULL, &a, &b);
    poly_basemul(&p, NULL, &b);
    poly_basemul(&p, &a, NULL);

    dsa_poly_ntt(NULL);
    dsa_poly_invntt(NULL);
    dsa_poly_pointwise(NULL, &da, &db);
    dsa_poly_pointwise(&dp, NULL, &db);
    dsa_poly_pointwise(&dp, &da, NULL);
    dsa_poly_tomont(NULL);

    return 0;
}
