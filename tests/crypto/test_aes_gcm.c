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
 * @brief Comprehensive unit tests for AES-128/256-GCM AEAD encryption, decryption,
 * boundaries, in-place execution, overlap rejection, and key lifecycle.
 */

#include <string.h>

#include "rivide/crypto/aes.h"
#include "rivide/crypto/aes_gcm.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

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

    rivide_aes_key_cleanse(&key);
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

    rivide_aes_key_cleanse(&key);
    return 0;
}

int test_aes_gcm_inplace(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    uint8_t iv[12];
    uint8_t buf[64];
    uint8_t original[64];
    uint8_t tag[16];
    uint8_t aad[20];

    rivide_randombytes(raw_key, sizeof(raw_key));
    rivide_randombytes(iv, sizeof(iv));
    rivide_randombytes(buf, sizeof(buf));
    rivide_randombytes(aad, sizeof(aad));
    memcpy(original, buf, sizeof(buf));

    ASSERT_OK(rivide_aes256_key_expand(&key, raw_key));

    /* In-place encryption (pt == ct) */
    ASSERT_OK(rivide_aes_gcm_encrypt(&key, iv, aad, sizeof(aad), buf, sizeof(buf), buf, tag));
    ASSERT_MEM_NE(buf, original, sizeof(buf));

    /* In-place decryption (ct == pt) */
    ASSERT_OK(rivide_aes_gcm_decrypt(&key, iv, aad, sizeof(aad), buf, sizeof(buf), tag, buf));
    ASSERT_MEM_EQ(buf, original, sizeof(buf));

    rivide_aes_key_cleanse(&key);
    return 0;
}

int test_aes_gcm_partial_overlap_rejection(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    uint8_t iv[12];
    uint8_t memory[128];
    uint8_t tag[16];

    rivide_randombytes(raw_key, sizeof(raw_key));
    rivide_randombytes(iv, sizeof(iv));
    rivide_randombytes(memory, sizeof(memory));

    ASSERT_OK(rivide_aes256_key_expand(&key, raw_key));

    /* Partial overlap: pt starts at memory[0], ct starts at memory[8], length 32 */
    uint8_t *pt = memory;
    uint8_t *ct = memory + 8;
    size_t len = 32;

    ASSERT_EQ(rivide_aes_gcm_encrypt(&key, iv, NULL, 0, pt, len, ct, tag),
              RIVIDE_ERR_INVALID_PARAM);
    ASSERT_EQ(rivide_aes_gcm_decrypt(&key, iv, NULL, 0, ct, len, tag, pt),
              RIVIDE_ERR_INVALID_PARAM);

    rivide_aes_key_cleanse(&key);
    return 0;
}

int test_aes_gcm_boundary_lengths(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    uint8_t iv[12];
    uint8_t pt_buf[64];
    uint8_t ct_buf[64];
    uint8_t dec_buf[64];
    uint8_t tag[16];
    static const size_t test_lens[] = {0, 1, 15, 16, 17, 31, 32, 33, 48, 64};
    size_t idx;

    rivide_randombytes(raw_key, sizeof(raw_key));
    rivide_randombytes(iv, sizeof(iv));
    rivide_randombytes(pt_buf, sizeof(pt_buf));

    ASSERT_OK(rivide_aes256_key_expand(&key, raw_key));

    for (idx = 0; idx < sizeof(test_lens) / sizeof(test_lens[0]); idx++) {
        size_t l = test_lens[idx];
        const uint8_t *in_pt = (l == 0) ? NULL : pt_buf;
        uint8_t *out_ct = (l == 0) ? NULL : ct_buf;
        uint8_t *out_dec = (l == 0) ? NULL : dec_buf;

        ASSERT_OK(rivide_aes_gcm_encrypt(&key, iv, NULL, 0, in_pt, l, out_ct, tag));
        ASSERT_OK(rivide_aes_gcm_decrypt(&key, iv, NULL, 0, out_ct, l, tag, out_dec));
        if (l > 0) {
            ASSERT_MEM_EQ(pt_buf, dec_buf, l);
        }
    }

    rivide_aes_key_cleanse(&key);
    return 0;
}

int test_aes_key_cleanse(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    size_t i;
    int all_zero = 1;

    rivide_randombytes(raw_key, sizeof(raw_key));
    ASSERT_OK(rivide_aes256_key_expand(&key, raw_key));
    ASSERT_EQ(key.rounds, 14);

    rivide_aes_key_cleanse(&key);
    ASSERT_EQ(key.rounds, 0);

    for (i = 0; i < sizeof(key.round_keys) / sizeof(key.round_keys[0]); i++) {
        if (key.round_keys[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    ASSERT_EQ(all_zero, 1);

    return 0;
}
