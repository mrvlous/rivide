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

#include <string.h>

#include "rivide/crypto/keccak.h"
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

    /* NULL input pointer with non-zero length must zeroize out and not forge empty hash */
    memset(out, 0xEE, sizeof(out));
    rivide_sha3_256(out, NULL, 32);
    static const uint8_t zeroes[32] = {0};
    ASSERT_MEM_EQ(out, zeroes, 32);

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

int test_sha3_512_empty(void) {
    uint8_t out[64];
    static const uint8_t zeroes[64] = {0};
    /* NIST FIPS 202 SHA3-512("") answer:
     * a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
     * 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26 */
    static const uint8_t expected[64] = {
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18,
        0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1,
        0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9,
        0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d,
        0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26};

    rivide_sha3_512(out, (const uint8_t *)"", 0);
    ASSERT_MEM_EQ(out, expected, 64);

    /* NULL input pointer with non-zero length must zeroize out and not forge empty hash */
    memset(out, 0xEE, sizeof(out));
    rivide_sha3_512(out, NULL, 64);
    ASSERT_MEM_EQ(out, zeroes, 64);

    return 0;
}

int test_shake256_incremental(void) {
    uint8_t out_oneshot[64];
    uint8_t out_inc[64];
    static const uint8_t msg[] =
        "Incremental absorption test for SHAKE256 engine across multiple chunks";
    rivide_keccak_state_t st;

    rivide_shake256(out_oneshot, 64, msg, sizeof(msg) - 1);

    rivide_shake256_init(&st);
    rivide_shake_absorb(&st, msg, 15);
    rivide_shake_absorb(&st, msg + 15, 20);
    rivide_shake_absorb(&st, msg + 35, sizeof(msg) - 1 - 35);
    rivide_shake_squeeze(&st, out_inc, 64);

    ASSERT_MEM_EQ(out_oneshot, out_inc, 64);

    return 0;
}

int test_keccak_sponge_state_invariants(void) {
    rivide_keccak_state_t ctx;
    uint8_t buf[32];
    uint8_t buf2[32];
    static const uint8_t data[] = "Sponge State Test";

    rivide_shake128_init(&ctx);
    rivide_shake_absorb(&ctx, data, sizeof(data));
    rivide_shake_squeeze(&ctx, buf, sizeof(buf));

    /* Absorbing after squeezing must be rejected and not corrupt state */
    rivide_shake_absorb(&ctx, data, sizeof(data));

    rivide_shake_squeeze(&ctx, buf2, sizeof(buf2));

    /* Squeezing unfinalized sponge must be rejected without modifying output */
    rivide_keccak_init(&ctx, 136);
    rivide_keccak_absorb(&ctx, data, sizeof(data));
    memset(buf, 0x55, sizeof(buf));
    rivide_keccak_squeeze(&ctx, buf, sizeof(buf));
    {
        uint8_t sentinel[32];
        memset(sentinel, 0x55, sizeof(sentinel));
        ASSERT_MEM_EQ(buf, sentinel, sizeof(buf));
    }
    rivide_keccak_f1600(NULL);
    rivide_shake128_init(NULL);
    rivide_shake256_init(NULL);
    rivide_shake_absorb(NULL, data, sizeof(data));
    rivide_shake_squeeze(NULL, buf, sizeof(buf));

    /* Invalid rate bounds guards */
    rivide_keccak_init(&ctx, 0);
    rivide_keccak_absorb(&ctx, data, sizeof(data));
    rivide_keccak_finalize(&ctx, 0x1F);
    rivide_keccak_squeeze(&ctx, buf, sizeof(buf));

    rivide_keccak_init(&ctx, 200);
    rivide_keccak_absorb(&ctx, data, sizeof(data));
    rivide_keccak_finalize(&ctx, 0x1F);
    rivide_keccak_squeeze(&ctx, buf, sizeof(buf));

    rivide_cleanse(&ctx, sizeof(ctx));
    return 0;
}
