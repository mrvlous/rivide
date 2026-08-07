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
 * @file aes_gcm.c
 * @brief AES-GCM AEAD implementation with software AES core and GHASH.
 *
 * This file implements the AES block cipher using a compact, constant-time
 * bitwise approach (avoiding classic T-tables to prevent cache-timing
 * side-channels on platforms without AES hardware acceleration), the GCM
 * mode of operation using GHASH multiplication in GF(2^128), and CTR-mode
 * encryption.
 */

#include "rivide/crypto/aes_gcm.h"

#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/**
 * @brief AES S-box lookup table.
 *
 * The SubBytes substitution table as defined in FIPS 197. Each byte of the
 * AES state is replaced by the corresponding entry in this table during
 * encryption rounds.
 */
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

/**
 * @brief AES round constants for key expansion.
 *
 * rcon[i] is the round constant for round i+1 of the key schedule.
 * Only the first byte is non-zero; the remaining three bytes are zero.
 */
static const uint8_t aes_rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/**
 * @brief Load a 32-bit big-endian value from a byte array.
 */
static uint32_t load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief Store a 32-bit value as big-endian bytes.
 */
static void store32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief Store a 64-bit value as big-endian bytes.
 */
static void store64_be(uint8_t *p, uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

/**
 * @brief Apply the SubWord transformation (four S-box lookups on a 32-bit word).
 */
static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)aes_sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xFF] << 8) | ((uint32_t)aes_sbox[w & 0xFF]);
}

/**
 * @brief Rotate a 32-bit word left by 8 bits.
 */
static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/**
 * @brief GF(2^8) multiplication by 2 (xtime) in the AES field.
 *
 * Used by MixColumns. The irreducible polynomial is x^8 + x^4 + x^3 + x + 1
 * (0x11B).
 */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

/**
 * @brief Encrypt a single 16-byte block with AES.
 *
 * @param[in]  key_ctx  Expanded key schedule.
 * @param[in]  in       16-byte input block.
 * @param[out] out      16-byte output block.
 */
static void aes_encrypt_block(const rivide_aes_key_t *key_ctx, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    int rounds = key_ctx->rounds;
    const uint32_t *rk = key_ctx->round_keys;
    int i, j, round;
    uint8_t t, u, v;

    /* Load input and apply initial AddRoundKey. */
    for (i = 0; i < 16; i++) {
        state[i] = in[i] ^ (uint8_t)(rk[i / 4] >> (24 - 8 * (i % 4)));
    }

    for (round = 1; round < rounds; round++) {
        uint8_t tmp[16];

        /* SubBytes */
        for (i = 0; i < 16; i++) {
            tmp[i] = aes_sbox[state[i]];
        }

        /* ShiftRows */
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

        /* MixColumns */
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

        /* AddRoundKey */
        for (i = 0; i < 16; i++) {
            state[i] ^= (uint8_t)(rk[round * 4 + i / 4] >> (24 - 8 * (i % 4)));
        }
    }

    /* Final round (no MixColumns). */
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

/**
 * @brief Increment the 32-bit counter portion of a GCM counter block.
 *
 * The counter occupies the last 4 bytes of the 16-byte block and is
 * incremented as a big-endian integer.
 *
 * @param[in,out] counter  16-byte counter block.
 */
static void gcm_inc_counter(uint8_t counter[16]) {
    uint32_t c = load32_be(counter + 12);
    c++;
    store32_be(counter + 12, c);
}

/**
 * @brief GHASH multiplication in GF(2^128).
 *
 * Multiplies two 128-bit values in the finite field GF(2^128) with the
 * irreducible polynomial x^128 + x^7 + x^2 + x + 1. This is the core
 * operation of GHASH, used to compute the authentication tag in GCM mode.
 *
 * @param[in,out] x  First operand (result is stored here).
 * @param[in]     y  Second operand (the hash subkey H).
 */
static void ghash_mult(uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    int i, j;

    for (i = 0; i < 16; i++) {
        v[i] = y[i];
    }

    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            if ((x[i] >> j) & 1) {
                int k;
                for (k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }

            /* Multiply v by x in GF(2^128): shift right, reduce. */
            {
                uint8_t carry = v[15] & 1;
                int k;
                for (k = 15; k > 0; k--) {
                    v[k] = (uint8_t)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
                }
                v[0] >>= 1;
                if (carry) {
                    v[0] ^= 0xE1; /* Reduction polynomial high byte. */
                }
            }
        }
    }

    for (i = 0; i < 16; i++) {
        x[i] = z[i];
    }
}

/**
 * @brief GHASH: hash a sequence of 16-byte blocks.
 *
 * @param[in]     h       16-byte GHASH subkey (H = AES_K(0^128)).
 * @param[in]     data    Input data (must be a multiple of 16 bytes if padded).
 * @param[in]     len     Length of input data in bytes.
 * @param[in,out] tag     Running GHASH accumulator (16 bytes).
 */
static void ghash_update(const uint8_t h[16], const uint8_t *data, size_t len, uint8_t tag[16]) {
    size_t i, j;
    uint8_t block[16];

    while (len > 0) {
        size_t chunk = (len >= 16) ? 16 : len;

        for (i = 0; i < 16; i++) {
            block[i] = 0;
        }
        for (i = 0; i < chunk; i++) {
            block[i] = data[i];
        }

        for (j = 0; j < 16; j++) {
            tag[j] ^= block[j];
        }
        ghash_mult(tag, h);

        data += chunk;
        len -= chunk;
    }
}

rivide_status_t rivide_aes_gcm_encrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len, const uint8_t *pt,
                                       size_t pt_len, uint8_t *ct, uint8_t *tag) {
    uint8_t h[16] = {0};
    uint8_t j0[16];
    uint8_t counter[16];
    uint8_t enc_block[16];
    uint8_t ghash_tag[16] = {0};
    uint8_t len_block[16];
    size_t i;

    if (!key || !iv || !ct || !tag) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (pt_len > 0 && !pt) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* Compute H = AES_K(0^128). */
    aes_encrypt_block(key, h, h);

    /* Build J0: IV || 0^31 || 1 (for 96-bit IV). */
    for (i = 0; i < 12; i++) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    /* CTR encryption starting from J0 + 1. */
    for (i = 0; i < 16; i++) {
        counter[i] = j0[i];
    }

    {
        size_t remaining = pt_len;
        size_t offset = 0;

        while (remaining > 0) {
            size_t chunk = (remaining >= 16) ? 16 : remaining;
            size_t k;

            gcm_inc_counter(counter);
            aes_encrypt_block(key, counter, enc_block);

            for (k = 0; k < chunk; k++) {
                ct[offset + k] = pt[offset + k] ^ enc_block[k];
            }

            offset += chunk;
            remaining -= chunk;
        }
    }

    /* GHASH over AAD and ciphertext. */
    if (aad_len > 0 && aad) {
        ghash_update(h, aad, aad_len, ghash_tag);
    }
    if (pt_len > 0) {
        ghash_update(h, ct, pt_len, ghash_tag);
    }

    /* Append lengths block: len(AAD) || len(CT) in bits, big-endian. */
    store64_be(len_block, (uint64_t)aad_len * 8);
    store64_be(len_block + 8, (uint64_t)pt_len * 8);
    ghash_update(h, len_block, 16, ghash_tag);

    /* Tag = GHASH XOR AES_K(J0). */
    aes_encrypt_block(key, j0, enc_block);
    for (i = 0; i < 16; i++) {
        tag[i] = ghash_tag[i] ^ enc_block[i];
    }

    rivide_cleanse(h, sizeof(h));
    rivide_cleanse(enc_block, sizeof(enc_block));
    rivide_cleanse(ghash_tag, sizeof(ghash_tag));

    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_aes_gcm_decrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                                       size_t ct_len, const uint8_t *tag, uint8_t *pt) {
    uint8_t h[16] = {0};
    uint8_t j0[16];
    uint8_t counter[16];
    uint8_t enc_block[16];
    uint8_t ghash_tag[16] = {0};
    uint8_t len_block[16];
    uint8_t computed_tag[16];
    size_t i;

    if (!key || !iv || !tag || !pt) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (ct_len > 0 && !ct) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* Compute H = AES_K(0^128). */
    aes_encrypt_block(key, h, h);

    /* Build J0. */
    for (i = 0; i < 12; i++) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    /* Compute GHASH over AAD and ciphertext BEFORE decryption. */
    if (aad_len > 0 && aad) {
        ghash_update(h, aad, aad_len, ghash_tag);
    }
    if (ct_len > 0) {
        ghash_update(h, ct, ct_len, ghash_tag);
    }

    store64_be(len_block, (uint64_t)aad_len * 8);
    store64_be(len_block + 8, (uint64_t)ct_len * 8);
    ghash_update(h, len_block, 16, ghash_tag);

    aes_encrypt_block(key, j0, enc_block);
    for (i = 0; i < 16; i++) {
        computed_tag[i] = ghash_tag[i] ^ enc_block[i];
    }

    /* Constant-time tag comparison. */
    if (rivide_ct_memcmp(computed_tag, tag, 16) != 0) {
        rivide_cleanse(pt, ct_len);
        rivide_cleanse(h, sizeof(h));
        rivide_cleanse(computed_tag, sizeof(computed_tag));
        return RIVIDE_ERR_VERIFICATION_FAILED;
    }

    /* CTR decryption. */
    for (i = 0; i < 16; i++) {
        counter[i] = j0[i];
    }

    {
        size_t remaining = ct_len;
        size_t offset = 0;

        while (remaining > 0) {
            size_t chunk = (remaining >= 16) ? 16 : remaining;
            size_t k;

            gcm_inc_counter(counter);
            aes_encrypt_block(key, counter, enc_block);

            for (k = 0; k < chunk; k++) {
                pt[offset + k] = ct[offset + k] ^ enc_block[k];
            }

            offset += chunk;
            remaining -= chunk;
        }
    }

    rivide_cleanse(h, sizeof(h));
    rivide_cleanse(enc_block, sizeof(enc_block));
    rivide_cleanse(ghash_tag, sizeof(ghash_tag));
    rivide_cleanse(computed_tag, sizeof(computed_tag));

    return RIVIDE_SUCCESS;
}
