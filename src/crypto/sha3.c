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
 * @file sha3.c
 * @brief SHA-3 and SHAKE public API implementations based on the Keccak engine.
 *
 * Provides one-shot and incremental hashing and Extendable-Output Functions (XOF)
 * for SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 specified in FIPS 202.
 */

#include "rivide/crypto/sha3.h"

#include "rivide/crypto/keccak.h"
#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/** @brief Domain separation byte for SHA-3 hash functions. */
#define SHA3_DOMAIN_SEP 0x06

/** @brief Domain separation byte for SHAKE extendable-output functions. */
#define SHAKE_DOMAIN_SEP 0x1F

/** @brief Sponge block rate in bytes for SHA3-256. */
#define SHA3_256_RATE 136

/** @brief Sponge block rate in bytes for SHA3-512. */
#define SHA3_512_RATE 72

/** @brief Sponge block rate in bytes for SHAKE-128. */
#define SHAKE128_RATE 168

/** @brief Sponge block rate in bytes for SHAKE-256. */
#define SHAKE256_RATE 136

/**
 * @brief Generic one-shot sponge hash wrapper.
 *
 * @param[out] out        Output byte buffer.
 * @param[in]  outlen     Number of output bytes.
 * @param[in]  in         Input message buffer.
 * @param[in]  inlen      Length of input message in bytes.
 * @param[in]  domain_sep Domain separation byte.
 * @param[in]  rate       Sponge rate in bytes.
 */
static void keccak_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                        uint8_t domain_sep, size_t rate) {
    rivide_keccak_state_t ctx;

    rivide_keccak_init(&ctx, rate);
    rivide_keccak_absorb(&ctx, in, inlen);
    rivide_keccak_finalize(&ctx, domain_sep);
    rivide_keccak_squeeze(&ctx, out, outlen);
    rivide_cleanse(&ctx, sizeof(ctx));
}

void rivide_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen) {
    keccak_hash(out, RIVIDE_SHA3_256_BYTES, in, inlen, SHA3_DOMAIN_SEP, SHA3_256_RATE);
}

void rivide_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen) {
    keccak_hash(out, RIVIDE_SHA3_512_BYTES, in, inlen, SHA3_DOMAIN_SEP, SHA3_512_RATE);
}

void rivide_shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak_hash(out, outlen, in, inlen, SHAKE_DOMAIN_SEP, SHAKE128_RATE);
}

void rivide_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak_hash(out, outlen, in, inlen, SHAKE_DOMAIN_SEP, SHAKE256_RATE);
}

void rivide_shake128_init(rivide_keccak_state_t *ctx) {
    rivide_keccak_init(ctx, SHAKE128_RATE);
}

void rivide_shake256_init(rivide_keccak_state_t *ctx) {
    rivide_keccak_init(ctx, SHAKE256_RATE);
}

void rivide_shake_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen) {
    rivide_keccak_absorb(ctx, in, inlen);
}

void rivide_shake_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) {
        rivide_keccak_finalize(ctx, SHAKE_DOMAIN_SEP);
    }
    rivide_keccak_squeeze(ctx, out, outlen);
}
