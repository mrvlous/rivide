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
 * @file test_sha3.c
 * @brief Unit tests for SHA-3 and SHAKE functions.
 */

#include "rivide/crypto/sha3.h"

#include "test_harness.h"

int test_sha3_256_empty(void) {
    uint8_t out[32];
    /* NIST FIPS 202 SHA3-256("") answer:
     * a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    static const uint8_t expected[32] = {0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
                                         0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
                                         0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
                                         0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a};

    rivide_sha3_256(out, (const uint8_t *)"", 0);
    ASSERT_MEM_EQ(out, expected, 32);

    return 0;
}

int test_shake128_incremental(void) {
    uint8_t out_oneshot[32];
    uint8_t out_inc[32];
    static const uint8_t msg[] = "Incremental absorption test for SHAKE128 engine";
    rivide_keccak_state_t st;

    rivide_shake128(out_oneshot, 32, msg, sizeof(msg) - 1);

    rivide_shake128_init(&st);
    rivide_shake_absorb(&st, msg, 10);
    rivide_shake_absorb(&st, msg + 10, sizeof(msg) - 1 - 10);
    rivide_shake_squeeze(&st, out_inc, 32);

    ASSERT_MEM_EQ(out_oneshot, out_inc, 32);

    return 0;
}
