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
 * @file aes_gcm.h
 * @brief AES-128/256-GCM Authenticated Encryption with Associated Data (AEAD).
 *
 * Provides AES-GCM encryption and decryption supporting both 128-bit and
 * 256-bit keys.
 */

#ifndef RIVIDE_CRYPTO_AES_GCM_H
#define RIVIDE_CRYPTO_AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/crypto/aes.h"
#include "rivide/rivide_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief GCM initialization vector size in bytes (96 bits). */
#define RIVIDE_GCM_IV_BYTES 12

/** @brief GCM authentication tag size in bytes (128 bits). */
#define RIVIDE_GCM_TAG_BYTES 16

/** @brief Maximum AES-GCM payload length in bytes per NIST SP 800-38D (2^39 - 256 bits). */
#define RIVIDE_GCM_MAX_PAYLOAD_BYTES ((uint64_t)0x0000000FFFFFFFF0ULL)

/** @brief Maximum AES-GCM AAD length in bytes per NIST SP 800-38D (2^64 - 1 bits). */
#define RIVIDE_GCM_MAX_AAD_BYTES ((uint64_t)0x1FFFFFFFFFFFFFFFULL)

/**
 * @brief AES-GCM authenticated encryption.
 *
 * Encrypts the plaintext and computes a 128-bit authentication tag over
 * the ciphertext and optional associated data (AAD).
 *
 * @param[in]  key     Expanded AES key schedule.
 * @param[in]  iv      12-byte initialization vector (nonce). Must be unique
 *                     per encryption with the same key.
 * @param[in]  aad     Associated data (authenticated but not encrypted).
 *                     May be NULL if @p aad_len is 0.
 * @param[in]  aad_len Length of AAD in bytes.
 * @param[in]  pt      Plaintext to encrypt.
 * @param[in]  pt_len  Length of plaintext in bytes.
 * @param[out] ct      Ciphertext output buffer (same size as plaintext).
 * @param[out] tag     16-byte authentication tag output.
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_aes_gcm_encrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len, const uint8_t *pt,
                                       size_t pt_len, uint8_t *ct, uint8_t *tag);

/**
 * @brief AES-GCM authenticated decryption.
 *
 * Decrypts the ciphertext and verifies the authentication tag. If tag
 * verification fails, the plaintext output is zeroed and an error is
 * returned to prevent use of unauthenticated data.
 *
 * @param[in]  key     Expanded AES key schedule.
 * @param[in]  iv      12-byte initialization vector (nonce).
 * @param[in]  aad     Associated data. May be NULL if @p aad_len is 0.
 * @param[in]  aad_len Length of AAD in bytes.
 * @param[in]  ct      Ciphertext to decrypt.
 * @param[in]  ct_len  Length of ciphertext in bytes.
 * @param[in]  tag     16-byte authentication tag to verify.
 * @param[out] pt      Plaintext output buffer (same size as ciphertext).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 * @return @ref RIVIDE_ERR_VERIFICATION_FAILED if the tag does not match.
 */
rivide_status_t rivide_aes_gcm_decrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                                       size_t ct_len, const uint8_t *tag, uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_CRYPTO_AES_GCM_H */
