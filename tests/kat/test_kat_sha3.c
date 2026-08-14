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
 * @file test_kat_sha3.c
 * @brief NIST FIPS 202 Known Answer Tests for SHA-3 and SHAKE XOF primitives.
 */

#include "test_kat_harness.h"

int kat_sha3_256_nist_vectors(void) {
    uint8_t out[32];
    uint8_t expected[32];

    /* Test Vector 1: Empty string */
    kat_hex_to_bytes(expected, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                     32);
    rivide_sha3_256(out, (const uint8_t *)"", 0);
    KAT_ASSERT_BYTES_EQ(out, expected, 32);

    /* Test Vector 2: "abc" */
    kat_hex_to_bytes(expected, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                     32);
    rivide_sha3_256(out, (const uint8_t *)"abc", 3);
    KAT_ASSERT_BYTES_EQ(out, expected, 32);

    return 0;
}

int kat_sha3_512_nist_vectors(void) {
    uint8_t out[64];
    uint8_t expected[64];

    /* Test Vector 1: Empty string */
    kat_hex_to_bytes(expected,
                     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                     "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                     64);
    rivide_sha3_512(out, (const uint8_t *)"", 0);
    KAT_ASSERT_BYTES_EQ(out, expected, 64);

    /* Test Vector 2: "abc" */
    kat_hex_to_bytes(expected,
                     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                     "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                     64);
    rivide_sha3_512(out, (const uint8_t *)"abc", 3);
    KAT_ASSERT_BYTES_EQ(out, expected, 64);

    return 0;
}

int kat_shake128_nist_vectors(void) {
    uint8_t out[32];
    uint8_t expected[32];

    /* Test Vector 1: Empty string (32 bytes squeeze) */
    kat_hex_to_bytes(expected, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                     32);
    rivide_shake128(out, 32, (const uint8_t *)"", 0);
    KAT_ASSERT_BYTES_EQ(out, expected, 32);

    /* Test Vector 2: "abc" (32 bytes squeeze) */
    kat_hex_to_bytes(expected, "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
                     32);
    rivide_shake128(out, 32, (const uint8_t *)"abc", 3);
    KAT_ASSERT_BYTES_EQ(out, expected, 32);

    return 0;
}

int kat_shake256_nist_vectors(void) {
    uint8_t out[64];
    uint8_t expected[64];

    /* Test Vector 1: Empty string (64 bytes squeeze) */
    kat_hex_to_bytes(expected,
                     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                     "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
                     64);
    rivide_shake256(out, 64, (const uint8_t *)"", 0);
    KAT_ASSERT_BYTES_EQ(out, expected, 64);

    /* Test Vector 2: "abc" (64 bytes squeeze) */
    kat_hex_to_bytes(expected,
                     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
                     "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
                     64);
    rivide_shake256(out, 64, (const uint8_t *)"abc", 3);
    KAT_ASSERT_BYTES_EQ(out, expected, 64);

    return 0;
}
