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
 * @brief AES-GCM AEAD mode implementation (CTR mode + GHASH authentication).
 *
 * Implements Galois/Counter Mode (GCM) authenticated encryption and decryption
 * conforming strictly to NIST SP 800-38D specifications, with overflow-safe
 * length checking, exact in-place buffer support, partial overlap rejection,
 * and comprehensive memory zeroization.
 */

#include "rivide/crypto/aes_gcm.h"

#include "rivide/crypto/aes.h"
#include "rivide/crypto/ghash.h"
#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

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
 * @brief Store a 32-bit integer into bytes in big-endian order.
 *
 * @param[out] p Output byte buffer.
 * @param[in]  v 32-bit integer to store.
 */
static inline void store32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief Store a 64-bit integer into bytes in big-endian order.
 *
 * @param[out] p Output byte buffer.
 * @param[in]  v 64-bit integer to store.
 */
static inline void store64_be(uint8_t *p, uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

/**
 * @brief Increment the 32-bit counter portion of a 128-bit GCM counter block.
 *
 * @param[in,out] counter 16-byte GCM counter block array.
 */
static inline void gcm_inc_counter(uint8_t counter[16]) {
    uint32_t c = load32_be(counter + 12);
    c++;
    store32_be(counter + 12, c);
}

/**
 * @brief Test whether two buffers of identical length partially overlap (unsafe aliasing).
 *
 * Exact in-place operation (a == b) is permitted and returns 0.
 *
 * @param[in] a   First buffer pointer.
 * @param[in] b   Second buffer pointer.
 * @param[in] len Length in bytes.
 * @return 1 if buffers partially overlap, 0 otherwise.
 */
static inline int buffers_overlap_partial(const void *a, const void *b, size_t len) {
    if (len == 0 || a == b || !a || !b) {
        return 0;
    }
    const uintptr_t p1 = (uintptr_t)a;
    const uintptr_t p2 = (uintptr_t)b;
    return (p1 < p2 + len && p2 < p1 + len);
}

/**
 * @brief Test whether two arbitrary memory ranges overlap.
 *
 * @param[in] a     First buffer pointer.
 * @param[in] len_a Length of first buffer in bytes.
 * @param[in] b     Second buffer pointer.
 * @param[in] len_b Length of second buffer in bytes.
 * @return 1 if ranges intersect, 0 otherwise.
 */
static inline int buffer_ranges_overlap(const void *a, size_t len_a, const void *b, size_t len_b) {
    if (len_a == 0 || len_b == 0 || !a || !b) {
        return 0;
    }
    const uintptr_t p1 = (uintptr_t)a;
    const uintptr_t p2 = (uintptr_t)b;
    return (p1 < p2 + len_b && p2 < p1 + len_a);
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

    /* 1. Pointer validation */
    if (!key || !iv || !tag) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (pt_len > 0 && (!pt || !ct)) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (aad_len > 0 && !aad) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* 2. NIST SP 800-38D Length bounds check */
    if ((uint64_t)pt_len > RIVIDE_GCM_MAX_PAYLOAD_BYTES ||
        (uint64_t)aad_len > RIVIDE_GCM_MAX_AAD_BYTES) {
        return RIVIDE_ERR_INVALID_PARAM;
    }

    /* 3. Buffer overlap validation (allow exact in-place pt == ct, reject partial overlap) */
    if (buffers_overlap_partial(pt, ct, pt_len)) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (pt_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, pt, pt_len) && tag != pt) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (pt_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, ct, pt_len) && tag != ct) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (aad_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, aad, aad_len)) {
        return RIVIDE_ERR_INVALID_PARAM;
    }

    /* 4. Compute H = AES_K(0^128). */
    rivide_aes_encrypt_block(key, h, h);

    /* 5. Build J0: IV || 0^31 || 1 (for 96-bit IV). */
    for (i = 0; i < 12; i++) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    /* 6. CTR encryption starting from J0 + 1. */
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
            rivide_aes_encrypt_block(key, counter, enc_block);

            for (k = 0; k < chunk; k++) {
                ct[offset + k] = (uint8_t)(pt[offset + k] ^ enc_block[k]);
            }

            offset += chunk;
            remaining -= chunk;
        }
    }

    /* 7. GHASH over AAD and ciphertext. */
    if (aad_len > 0 && aad) {
        rivide_ghash_update(h, aad, aad_len, ghash_tag);
    }
    if (pt_len > 0) {
        rivide_ghash_update(h, ct, pt_len, ghash_tag);
    }

    /* 8. Append lengths block: len(AAD) || len(CT) in bits, big-endian. */
    store64_be(len_block, (uint64_t)aad_len * 8);
    store64_be(len_block + 8, (uint64_t)pt_len * 8);
    rivide_ghash_update(h, len_block, 16, ghash_tag);

    /* 9. Tag = GHASH XOR AES_K(J0). */
    rivide_aes_encrypt_block(key, j0, enc_block);
    for (i = 0; i < 16; i++) {
        tag[i] = (uint8_t)(ghash_tag[i] ^ enc_block[i]);
    }

    /* 10. Cleanse all sensitive intermediate stack state. */
    rivide_cleanse(h, sizeof(h));
    rivide_cleanse(j0, sizeof(j0));
    rivide_cleanse(counter, sizeof(counter));
    rivide_cleanse(enc_block, sizeof(enc_block));
    rivide_cleanse(ghash_tag, sizeof(ghash_tag));
    rivide_cleanse(len_block, sizeof(len_block));

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

    /* 1. Pointer validation */
    if (!key || !iv || !tag) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (ct_len > 0 && (!ct || !pt)) {
        return RIVIDE_ERR_NULL_PTR;
    }
    if (aad_len > 0 && !aad) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* 2. NIST SP 800-38D Length bounds check */
    if ((uint64_t)ct_len > RIVIDE_GCM_MAX_PAYLOAD_BYTES ||
        (uint64_t)aad_len > RIVIDE_GCM_MAX_AAD_BYTES) {
        return RIVIDE_ERR_INVALID_PARAM;
    }

    /* 3. Buffer overlap validation (allow exact in-place ct == pt, reject partial overlap) */
    if (buffers_overlap_partial(ct, pt, ct_len)) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (ct_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, pt, ct_len) && tag != pt) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (ct_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, ct, ct_len) && tag != ct) {
        return RIVIDE_ERR_INVALID_PARAM;
    }
    if (aad_len > 0 && buffer_ranges_overlap(tag, RIVIDE_GCM_TAG_BYTES, aad, aad_len)) {
        return RIVIDE_ERR_INVALID_PARAM;
    }

    /* 4. Compute H = AES_K(0^128). */
    rivide_aes_encrypt_block(key, h, h);

    /* 5. Build J0. */
    for (i = 0; i < 12; i++) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    /* 6. Compute GHASH over AAD and ciphertext BEFORE decryption. */
    if (aad_len > 0 && aad) {
        rivide_ghash_update(h, aad, aad_len, ghash_tag);
    }
    if (ct_len > 0) {
        rivide_ghash_update(h, ct, ct_len, ghash_tag);
    }

    store64_be(len_block, (uint64_t)aad_len * 8);
    store64_be(len_block + 8, (uint64_t)ct_len * 8);
    rivide_ghash_update(h, len_block, 16, ghash_tag);

    rivide_aes_encrypt_block(key, j0, enc_block);
    for (i = 0; i < 16; i++) {
        computed_tag[i] = (uint8_t)(ghash_tag[i] ^ enc_block[i]);
    }

    /* 7. CTR decryption. */
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
            rivide_aes_encrypt_block(key, counter, enc_block);

            for (k = 0; k < chunk; k++) {
                pt[offset + k] = (uint8_t)(ct[offset + k] ^ enc_block[k]);
            }

            offset += chunk;
            remaining -= chunk;
        }
    }

    /* 8. Cleanse all sensitive intermediate stack state. */
    rivide_cleanse(h, sizeof(h));
    rivide_cleanse(j0, sizeof(j0));
    rivide_cleanse(counter, sizeof(counter));
    rivide_cleanse(enc_block, sizeof(enc_block));
    rivide_cleanse(ghash_tag, sizeof(ghash_tag));
    rivide_cleanse(len_block, sizeof(len_block));

    /* 9. Constant-time tag comparison and conditional failure zeroization. */
    if (rivide_ct_memcmp(computed_tag, tag, 16) != 0) {
        if (pt && ct_len > 0) {
            rivide_cleanse(pt, ct_len);
        }
        rivide_cleanse(computed_tag, sizeof(computed_tag));
        return RIVIDE_ERR_VERIFICATION_FAILED;
    }

    rivide_cleanse(computed_tag, sizeof(computed_tag));

    return RIVIDE_SUCCESS;
}
