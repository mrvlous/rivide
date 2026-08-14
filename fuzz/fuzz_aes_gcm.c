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
 * @file fuzz_aes_gcm.c
 * @brief LLVM libFuzzer target for AES-128-GCM and AES-256-GCM authenticated decryption.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rivide/crypto/aes_gcm.h"
#include "rivide/rivide.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        rivide_init();
        initialized = 1;
    }

    /* Need at least: 32 bytes key + 12 bytes IV + 16 bytes Tag = 60 bytes */
    if (size < 60) {
        return 0;
    }

    const uint8_t *key_raw = data;
    const uint8_t *iv = data + 32;
    const uint8_t *tag = data + 32 + 12;
    const uint8_t *ct = data + 60;
    size_t ct_len = size - 60;

    uint8_t plaintext[1024];
    size_t test_len = (ct_len < sizeof(plaintext)) ? ct_len : sizeof(plaintext);

    rivide_aes_key_t key128, key256;

    /* Fuzz AES-128-GCM decryption */
    if (rivide_aes128_key_expand(&key128, key_raw) == RIVIDE_SUCCESS) {
        rivide_aes_gcm_decrypt(&key128, iv, NULL, 0, ct, test_len, tag, plaintext);
    }

    /* Fuzz AES-256-GCM decryption */
    if (rivide_aes256_key_expand(&key256, key_raw) == RIVIDE_SUCCESS) {
        rivide_aes_gcm_decrypt(&key256, iv, NULL, 0, ct, test_len, tag, plaintext);
    }

    return 0;
}
