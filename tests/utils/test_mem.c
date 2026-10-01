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
 * @file test_mem.c
 * @brief Unit tests for constant-time memory utilities.
 */

#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

#include "test_harness.h"

int test_ct_memcmp(void) {
    uint8_t a[32] = {0xAA, 0xBB, 0xCC};
    uint8_t b[32] = {0xAA, 0xBB, 0xCC};
    uint8_t c[32] = {0xAA, 0xBB, 0xDD};

    ASSERT_EQ(rivide_ct_memcmp(a, b, 32), 0);
    ASSERT_EQ(rivide_ct_memcmp(a, c, 32) != 0, 1);

    return 0;
}

int test_ct_select(void) {
    uint8_t a[16] = {0x11, 0x11, 0x11, 0x11};
    uint8_t b[16] = {0x22, 0x22, 0x22, 0x22};
    uint8_t dst[16];

    rivide_ct_select(dst, a, b, 16, 0);
    ASSERT_MEM_EQ(dst, a, 16);

    rivide_ct_select(dst, a, b, 16, 1);
    ASSERT_MEM_EQ(dst, b, 16);

    return 0;
}

static rivide_status_t mock_deterministic_rng(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA5 ^ (uint8_t)i);
    }
    return RIVIDE_SUCCESS;
}

int test_random_bounds_and_callback(void) {
    uint8_t buf1[32] = {0};
    uint8_t buf2[32] = {0};
    size_t i;
    int is_different = 0;

    /* 1. Zero length must be valid no-op */
    ASSERT_EQ(rivide_randombytes(NULL, 0), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_randombytes(buf1, 0), RIVIDE_SUCCESS);

    /* 2. NULL pointer with non-zero length must fail */
    ASSERT_EQ(rivide_randombytes(NULL, 16), RIVIDE_ERR_NULL_PTR);

    /* 3. Normal OS randombytes generation */
    ASSERT_EQ(rivide_randombytes(buf1, 32), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_randombytes(buf2, 32), RIVIDE_SUCCESS);
    for (i = 0; i < 32; i++) {
        if (buf1[i] != buf2[i]) {
            is_different = 1;
            break;
        }
    }
    ASSERT_EQ(is_different, 1);

    /* 4. Custom RNG callback registration */
    ASSERT_EQ(rivide_set_rng_callback(mock_deterministic_rng), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_randombytes(buf1, 32), RIVIDE_SUCCESS);
    for (i = 0; i < 32; i++) {
        ASSERT_EQ(buf1[i], (uint8_t)(0xA5 ^ (uint8_t)i));
    }

    /* 5. Reset RNG callback back to OS default via rivide_reset_rng_callback */
    ASSERT_EQ(rivide_reset_rng_callback(), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_randombytes(buf1, 32), RIVIDE_SUCCESS);
    /* Should no longer match deterministic mock */
    ASSERT_EQ(buf1[0] == 0xA5 && buf1[1] == (0xA5 ^ 1) && buf1[2] == (0xA5 ^ 2), 0);

    /* 6. Reset RNG callback via passing NULL to rivide_set_rng_callback */
    ASSERT_EQ(rivide_set_rng_callback(mock_deterministic_rng), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_set_rng_callback(NULL), RIVIDE_SUCCESS);
    ASSERT_EQ(rivide_randombytes(buf1, 32), RIVIDE_SUCCESS);
    ASSERT_EQ(buf1[0] == 0xA5 && buf1[1] == (0xA5 ^ 1) && buf1[2] == (0xA5 ^ 2), 0);

    return 0;
}
