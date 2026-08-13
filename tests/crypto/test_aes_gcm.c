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
 * @file test_aes_gcm.c
 * @brief Unit tests for AES-128/256-GCM AEAD encryption and decryption.
 */

#include "rivide/crypto/aes_gcm.h"

#include "test_harness.h"

int test_aes128_gcm_roundtrip(void) {
    rivide_aes_key_t key;
    static const uint8_t raw_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    static const uint8_t iv[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                   0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};
    static const uint8_t aad[] = "Associated Data";
    static const uint8_t pt[] = "Secret Plaintext Message for AES-GCM";
    uint8_t ct[sizeof(pt)];
    uint8_t tag[16];
    uint8_t recovered[sizeof(pt)];

    ASSERT_OK(rivide_aes128_key_expand(&key, raw_key));
    ASSERT_OK(rivide_aes_gcm_encrypt(&key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, tag));
    ASSERT_OK(rivide_aes_gcm_decrypt(&key, iv, aad, sizeof(aad), ct, sizeof(pt), tag, recovered));

    ASSERT_MEM_EQ(pt, recovered, sizeof(pt));

    return 0;
}

int test_aes256_gcm_invalid_tag(void) {
    rivide_aes_key_t key;
    static const uint8_t raw_key[32] = {0};
    static const uint8_t iv[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    static const uint8_t pt[] = "Data to protect";
    uint8_t ct[sizeof(pt)];
    uint8_t tag[16];
    uint8_t recovered[sizeof(pt)];

    ASSERT_OK(rivide_aes256_key_expand(&key, raw_key));
    ASSERT_OK(rivide_aes_gcm_encrypt(&key, iv, NULL, 0, pt, sizeof(pt), ct, tag));

    /* Tamper tag. */
    tag[0] ^= 0x01;

    ASSERT_FAIL(rivide_aes_gcm_decrypt(&key, iv, NULL, 0, ct, sizeof(pt), tag, recovered));

    return 0;
}
