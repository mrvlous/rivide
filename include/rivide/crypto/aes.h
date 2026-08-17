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
 * @file aes.h
 * @brief AES block cipher key schedule definitions and expansion API.
 */

#ifndef RIVIDE_CRYPTO_AES_H
#define RIVIDE_CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/rivide_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief AES block size in bytes. */
#define RIVIDE_AES_BLOCK_BYTES 16

/** @brief AES-128 key size in bytes. */
#define RIVIDE_AES128_KEY_BYTES 16

/** @brief AES-256 key size in bytes. */
#define RIVIDE_AES256_KEY_BYTES 32

/** @brief Maximum number of AES round keys (AES-256: 14 rounds + 1 initial). */
#define RIVIDE_AES_MAX_ROUNDS 15

/**
 * @brief AES expanded key schedule.
 */
typedef struct rivide_aes_key {
    /** @brief Expanded round keys. */
    uint32_t round_keys[4 * (RIVIDE_AES_MAX_ROUNDS + 1)];

    /** @brief Number of AES rounds (10 for AES-128, 14 for AES-256). */
    int rounds;
} rivide_aes_key_t;

/**
 * @brief Expand an AES-128 key into a key schedule.
 */
rivide_status_t rivide_aes128_key_expand(rivide_aes_key_t *ctx, const uint8_t *key);

/**
 * @brief Expand an AES-256 key into a key schedule.
 */
rivide_status_t rivide_aes256_key_expand(rivide_aes_key_t *ctx, const uint8_t *key);

/**
 * @brief Encrypt a single 16-byte block with AES.
 */
void rivide_aes_encrypt_block(const rivide_aes_key_t *key_ctx, const uint8_t *in, uint8_t *out);

/**
 * @brief Securely zeroize an expanded AES key context.
 *
 * @param[in,out] ctx Key context to cleanse.
 */
void rivide_aes_key_cleanse(rivide_aes_key_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_CRYPTO_AES_H */
