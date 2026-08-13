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
 * @brief Unit tests for SIMD vector polynomial addition and subtraction.
 */

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
