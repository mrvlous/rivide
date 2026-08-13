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
 * @file aes_core.c
 * @brief AES block cipher S-box, round constants, key expansion, and single block encryption.
 *
 * Implements standard AES-128 and AES-256 Rijndael block cipher transformations
 * without precomputed T-tables to mitigate cache-timing side-channel attacks.
 */

#include "rivide/crypto/aes.h"
#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/** @brief Standard AES forward Substitution Box (S-box). */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/** @brief AES round constant table (rcon). */
static const uint8_t aes_rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/**
 * @brief Load a big-endian 32-bit integer from bytes.
 *
 * @param[in] p Input byte buffer.
 * @return Loaded 32-bit unsigned integer.
 */
static uint32_t load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief Substitute all 4 bytes of a 32-bit word using the AES S-box.
 *
 * @param[in] w Input 32-bit word.
 * @return Substituted 32-bit word.
 */
static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)aes_sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xFF] << 8) | ((uint32_t)aes_sbox[w & 0xFF]);
}

/**
 * @brief Rotate a 32-bit word left by 8 bits (1 byte).
 *
 * @param[in] w Input 32-bit word.
 * @return Rotated 32-bit word.
 */
static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/**
 * @brief Multiply a byte by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x1B).
 *
 * @param[in] x Input byte.
 * @return Product byte in GF(2^8).
 */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

/**
 * @brief Encrypt a single 16-byte block with AES.
 *
 * @param[in]  key_ctx Expanded AES key schedule context.
 * @param[in]  in      16-byte input block to encrypt.
 * @param[out] out     16-byte output ciphertext block.
 */
void rivide_aes_encrypt_block(const rivide_aes_key_t *key_ctx, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    int rounds = key_ctx->rounds;
    const uint32_t *rk = key_ctx->round_keys;
    int i, j, round;
    uint8_t t, u, v;

    for (i = 0; i < 16; i++) {
        state[i] = in[i] ^ (uint8_t)(rk[i / 4] >> (24 - 8 * (i % 4)));
    }

    for (round = 1; round < rounds; round++) {
        uint8_t tmp[16];

        for (i = 0; i < 16; i++) {
            tmp[i] = aes_sbox[state[i]];
        }

        state[0] = tmp[0];
        state[1] = tmp[5];
        state[2] = tmp[10];
        state[3] = tmp[15];
        state[4] = tmp[4];
        state[5] = tmp[9];
        state[6] = tmp[14];
        state[7] = tmp[3];
        state[8] = tmp[8];
        state[9] = tmp[13];
        state[10] = tmp[2];
        state[11] = tmp[7];
        state[12] = tmp[12];
        state[13] = tmp[1];
        state[14] = tmp[6];
        state[15] = tmp[11];

        for (j = 0; j < 4; j++) {
            int base = j * 4;
            t = state[base] ^ state[base + 1] ^ state[base + 2] ^ state[base + 3];
            u = state[base];
            v = (uint8_t)(state[base] ^ state[base + 1]);
            v = xtime(v);
            state[base] ^= v ^ t;
            v = (uint8_t)(state[base + 1] ^ state[base + 2]);
            v = xtime(v);
            state[base + 1] ^= v ^ t;
            v = (uint8_t)(state[base + 2] ^ state[base + 3]);
            v = xtime(v);
            state[base + 2] ^= v ^ t;
            v = (uint8_t)(state[base + 3] ^ u);
            v = xtime(v);
            state[base + 3] ^= v ^ t;
        }

        for (i = 0; i < 16; i++) {
            state[i] ^= (uint8_t)(rk[round * 4 + i / 4] >> (24 - 8 * (i % 4)));
        }
    }

    {
        uint8_t tmp[16];
        for (i = 0; i < 16; i++) {
            tmp[i] = aes_sbox[state[i]];
        }

        state[0] = tmp[0];
        state[1] = tmp[5];
        state[2] = tmp[10];
        state[3] = tmp[15];
        state[4] = tmp[4];
        state[5] = tmp[9];
        state[6] = tmp[14];
        state[7] = tmp[3];
        state[8] = tmp[8];
        state[9] = tmp[13];
        state[10] = tmp[2];
        state[11] = tmp[7];
        state[12] = tmp[12];
        state[13] = tmp[1];
        state[14] = tmp[6];
        state[15] = tmp[11];

        for (i = 0; i < 16; i++) {
            state[i] ^= (uint8_t)(rk[rounds * 4 + i / 4] >> (24 - 8 * (i % 4)));
        }
    }

    for (i = 0; i < 16; i++) {
        out[i] = state[i];
    }

    rivide_cleanse(state, sizeof(state));
}

/**
 * @brief Expand an AES-128 key into a round key schedule context.
 *
 * @param[out] ctx Output key schedule context structure.
 * @param[in]  key Input 16-byte raw key.
 * @return @ref RIVIDE_SUCCESS on success, or @ref RIVIDE_ERR_NULL_PTR if an argument is NULL.
 */
rivide_status_t rivide_aes128_key_expand(rivide_aes_key_t *ctx, const uint8_t *key) {
    int i;

    if (!ctx || !key) {
        return RIVIDE_ERR_NULL_PTR;
    }

    ctx->rounds = 10;

    for (i = 0; i < 4; i++) {
        ctx->round_keys[i] = load32_be(key + 4 * i);
    }

    for (i = 4; i < 44; i++) {
        uint32_t tmp = ctx->round_keys[i - 1];
        if (i % 4 == 0) {
            tmp = sub_word(rot_word(tmp)) ^ ((uint32_t)aes_rcon[i / 4 - 1] << 24);
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4] ^ tmp;
    }

    return RIVIDE_SUCCESS;
}

/**
 * @brief Expand an AES-256 key into a round key schedule context.
 *
 * @param[out] ctx Output key schedule context structure.
 * @param[in]  key Input 32-byte raw key.
 * @return @ref RIVIDE_SUCCESS on success, or @ref RIVIDE_ERR_NULL_PTR if an argument is NULL.
 */
rivide_status_t rivide_aes256_key_expand(rivide_aes_key_t *ctx, const uint8_t *key) {
    int i;

    if (!ctx || !key) {
        return RIVIDE_ERR_NULL_PTR;
    }

    ctx->rounds = 14;

    for (i = 0; i < 8; i++) {
        ctx->round_keys[i] = load32_be(key + 4 * i);
    }

    for (i = 8; i < 60; i++) {
        uint32_t tmp = ctx->round_keys[i - 1];
        if (i % 8 == 0) {
            tmp = sub_word(rot_word(tmp)) ^ ((uint32_t)aes_rcon[i / 8 - 1] << 24);
        } else if (i % 8 == 4) {
            tmp = sub_word(tmp);
        }
        ctx->round_keys[i] = ctx->round_keys[i - 8] ^ tmp;
    }

    return RIVIDE_SUCCESS;
}
