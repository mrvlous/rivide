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
