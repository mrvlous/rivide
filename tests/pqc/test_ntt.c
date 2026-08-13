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
#include "rivide/internal/dsa_poly.h"
#include "rivide/internal/dsa_reduce.h"
#include "rivide/internal/kem_ntt.h"
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
