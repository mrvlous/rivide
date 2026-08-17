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
 * with a strictly table-free, constant-time algebraic GF(2^8) S-box to completely
 * mitigate cache-timing and microarchitectural side-channel attacks.
 */

#include "rivide/crypto/aes.h"
#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/** @brief AES round constant table (rcon) indexed solely by public round numbers. */
static const uint8_t aes_rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/**
 * @brief Load a big-endian 32-bit integer from bytes.
 *
 * @param[in] p Input byte buffer.
 * @return Loaded 32-bit unsigned integer.
 */
static inline uint32_t load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief Branchless constant-time multiplication by x in GF(2^8) modulo 0x11B.
 *
 * @param[in] x Input byte.
 * @return Product byte in GF(2^8).
 */
static inline uint8_t gf256_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((uint8_t)(0 - (x >> 7))) & 0x1B));
}

/**
 * @brief Branchless constant-time multiplication of two elements in GF(2^8).
 *
 * @param[in] a First element in GF(2^8).
 * @param[in] b Second element in GF(2^8).
 * @return Product a * b in GF(2^8).
 */
static inline uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0 - (b & 1));
        p ^= (a & mask);
        a = gf256_xtime(a);
        b >>= 1;
    }
    return p;
}

/**
 * @brief Branchless constant-time squaring in GF(2^8).
 *
 * @param[in] a Element in GF(2^8).
 * @return a^2 in GF(2^8).
 */
static inline uint8_t gf256_sqr(uint8_t a) {
    return gf256_mul(a, a);
}

/**
 * @brief Branchless constant-time multiplicative inversion in GF(2^8).
 *
 * Computes a^254 in GF(2^8) via addition chain. Maps 0 to 0 naturally.
 *
 * @param[in] a Element in GF(2^8).
 * @return Multiplicative inverse of a in GF(2^8), or 0 if a == 0.
 */
static inline uint8_t gf256_inv(uint8_t a) {
    uint8_t a2 = gf256_sqr(a);
    uint8_t a3 = gf256_mul(a2, a);
    uint8_t a6 = gf256_sqr(a3);
    uint8_t a7 = gf256_mul(a6, a);
    uint8_t a14 = gf256_sqr(a7);
    uint8_t a15 = gf256_mul(a14, a);
    uint8_t a30 = gf256_sqr(a15);
    uint8_t a60 = gf256_sqr(a30);
    uint8_t a63 = gf256_mul(a60, a3);
    uint8_t a126 = gf256_sqr(a63);
    uint8_t a127 = gf256_mul(a126, a);
    return gf256_sqr(a127);
}

/**
 * @brief 8-bit left circular rotation.
 *
 * @param[in] x Input byte.
 * @param[in] n Rotation distance (1 to 7).
 * @return Rotated byte.
 */
static inline uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

/**
 * @brief Table-free, branchless constant-time AES forward S-box evaluation.
 *
 * Performs algebraic inversion in GF(2^8) followed by the FIPS 197 affine transformation.
 * Contains 0 table lookups and 0 secret-dependent branches.
 *
 * @param[in] in Input byte.
 * @return Substituted byte.
 */
static inline uint8_t aes_sbox_ct(uint8_t in) {
    uint8_t inv = gf256_inv(in);
    return (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
}

/**
 * @brief Substitute all 4 bytes of a 32-bit word using constant-time AES S-box.
 *
 * @param[in] w Input 32-bit word.
 * @return Substituted 32-bit word.
 */
static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)aes_sbox_ct((uint8_t)(w >> 24)) << 24) |
           ((uint32_t)aes_sbox_ct((uint8_t)(w >> 16)) << 16) |
           ((uint32_t)aes_sbox_ct((uint8_t)(w >> 8)) << 8) | ((uint32_t)aes_sbox_ct((uint8_t)w));
}

/**
 * @brief Rotate a 32-bit word left by 8 bits (1 byte).
 *
 * @param[in] w Input 32-bit word.
 * @return Rotated 32-bit word.
 */
static inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/**
 * @brief Encrypt a single 16-byte block with AES in constant time.
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
            tmp[i] = aes_sbox_ct(state[i]);
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
            t = (uint8_t)(state[base] ^ state[base + 1] ^ state[base + 2] ^ state[base + 3]);
            u = state[base];
            v = (uint8_t)(state[base] ^ state[base + 1]);
            v = gf256_xtime(v);
            state[base] ^= (uint8_t)(v ^ t);
            v = (uint8_t)(state[base + 1] ^ state[base + 2]);
            v = gf256_xtime(v);
            state[base + 1] ^= (uint8_t)(v ^ t);
            v = (uint8_t)(state[base + 2] ^ state[base + 3]);
            v = gf256_xtime(v);
            state[base + 2] ^= (uint8_t)(v ^ t);
            v = (uint8_t)(state[base + 3] ^ u);
            v = gf256_xtime(v);
            state[base + 3] ^= (uint8_t)(v ^ t);
        }

        for (i = 0; i < 16; i++) {
            state[i] ^= (uint8_t)(rk[round * 4 + i / 4] >> (24 - 8 * (i % 4)));
        }
    }

    {
        uint8_t tmp[16];
        for (i = 0; i < 16; i++) {
            tmp[i] = aes_sbox_ct(state[i]);
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
 * @brief Securely zeroize an expanded AES key context.
 *
 * @param[in,out] ctx Key context to cleanse.
 */
void rivide_aes_key_cleanse(rivide_aes_key_t *ctx) {
    if (ctx) {
        rivide_cleanse(ctx->round_keys, sizeof(ctx->round_keys));
        ctx->rounds = 0;
    }
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
