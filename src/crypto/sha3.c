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
 * @brief Keccak-f[1600] permutation and FIPS 202 SHA-3 / SHAKE implementation.
 *
 * This file implements the complete Keccak-f[1600] permutation (24 rounds of
 * the five step mappings: theta, rho, pi, chi, iota) and the sponge
 * construction used by SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256.
 *
 * The implementation operates on 64-bit lanes and includes portable
 * little-endian load/store helpers for cross-platform correctness.
 */

#include "rivide/crypto/sha3.h"

#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/** @brief Number of rounds in the Keccak-f[1600] permutation. */
#define KECCAK_ROUNDS 24

/** @brief SHA-3 domain separation byte (FIPS 202 Section 6.1). */
#define SHA3_DOMAIN_SEP 0x06

/** @brief SHAKE domain separation byte (FIPS 202 Section 6.2). */
#define SHAKE_DOMAIN_SEP 0x1F

/** @brief Sponge rate for SHA3-256 in bytes (1600 - 2*256) / 8 = 136. */
#define SHA3_256_RATE 136

/** @brief Sponge rate for SHA3-512 in bytes (1600 - 2*512) / 8 = 72. */
#define SHA3_512_RATE 72

/** @brief Sponge rate for SHAKE-128 in bytes (1600 - 2*128) / 8 = 168. */
#define SHAKE128_RATE 168

/** @brief Sponge rate for SHAKE-256 in bytes (1600 - 2*256) / 8 = 136. */
#define SHAKE256_RATE 136

/**
 * @brief Round constants for the iota step of Keccak-f[1600].
 *
 * These 24 constants are derived from the output of a linear feedback shift
 * register as specified in the Keccak reference (Section 1.2).
 */
static const uint64_t keccak_rc[KECCAK_ROUNDS] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808A),
    UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008A),
    UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B), UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A), UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)};

/**
 * @brief Rotation offsets for the rho step.
 *
 * Indexed as rho_offsets[5*y + x] for lane (x, y), with (0,0) having
 * offset 0 (identity). The offsets are specified in the Keccak reference.
 */
static const unsigned int rho_offsets[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                                             25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};

/**
 * @brief Rotate a 64-bit value left by @p n bits.
 *
 * @param[in] x  Value to rotate.
 * @param[in] n  Number of bit positions (0 <= n < 64).
 * @return The rotated value.
 */
static uint64_t rotl64(uint64_t x, unsigned int n) {
    if (n == 0) {
        return x;
    }
    return (x << n) | (x >> (64 - n));
}

/**
 * @brief Execute the Keccak-f[1600] permutation on a 25-lane state.
 *
 * Applies 24 rounds of the five step mappings (theta, rho, pi, chi, iota)
 * to the state array in-place.
 *
 * @param[in,out] state  Array of 25 uint64_t lanes representing the
 *                       1600-bit Keccak state.
 */
static void keccak_f1600(uint64_t state[25]) {
    int round;
    uint64_t C[5], D[5], B[25], t;
    int x, y;

    for (round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step: compute column parities and XOR with neighbors. */
        for (x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                state[5 * y + x] ^= D[x];
            }
        }

        /* Rho and Pi steps: rotate each lane and rearrange positions. */
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                int idx = 5 * y + x;
                B[5 * ((2 * x + 3 * y) % 5) + y] = rotl64(state[idx], rho_offsets[idx]);
            }
        }

        /* Chi step: non-linear mixing within each row. */
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                state[5 * y + x] =
                    B[5 * y + x] ^ (~B[5 * y + (x + 1) % 5] & B[5 * y + (x + 2) % 5]);
            }
        }

        /* Iota step: break symmetry with round constant. */
        state[0] ^= keccak_rc[round];
    }

    (void)t;
}

/**
 * @brief Zero-initialize a Keccak state.
 *
 * @param[out] ctx   Keccak state to initialize.
 * @param[in]  rate  Sponge rate in bytes.
 */
static void keccak_init(rivide_keccak_state_t *ctx, size_t rate) {
    size_t i;
    for (i = 0; i < 25; i++) {
        ctx->state[i] = 0;
    }
    ctx->absorbed = 0;
    ctx->rate = rate;
    ctx->squeezing = 0;
}

/**
 * @brief Absorb input data into the Keccak sponge.
 *
 * @param[in,out] ctx    Initialized Keccak state.
 * @param[in]     in     Input data.
 * @param[in]     inlen  Length of input data in bytes.
 */
static void keccak_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen) {
    size_t rate = ctx->rate;
    size_t absorbed = ctx->absorbed;

    while (inlen > 0) {
        size_t avail = rate - absorbed;
        size_t chunk = (inlen < avail) ? inlen : avail;

        /*
         * We need to XOR input bytes into the state at the correct offset.
         * Process byte-by-byte for the partial-block case to maintain
         * correct lane alignment.
         */
        {
            size_t i;
            for (i = 0; i < chunk; i++) {
                size_t pos = absorbed + i;
                size_t lane = pos / 8;
                size_t offset = pos % 8;
                ctx->state[lane] ^= (uint64_t)in[i] << (8 * offset);
            }
        }

        absorbed += chunk;
        in += chunk;
        inlen -= chunk;

        if (absorbed == rate) {
            keccak_f1600(ctx->state);
            absorbed = 0;
        }
    }

    ctx->absorbed = absorbed;
}

/**
 * @brief Finalize the absorb phase with domain separation and padding.
 *
 * Applies the FIPS 202 multi-rate padding rule: domain_sep byte at the
 * current position, 0x80 at the last byte of the rate block, then permute.
 *
 * @param[in,out] ctx         Keccak state.
 * @param[in]     domain_sep  Domain separation byte (0x06 for SHA-3, 0x1F for SHAKE).
 */
static void keccak_finalize(rivide_keccak_state_t *ctx, uint8_t domain_sep) {
    size_t absorbed = ctx->absorbed;
    size_t rate = ctx->rate;
    size_t lane, offset;

    /* XOR domain separation byte at current position. */
    lane = absorbed / 8;
    offset = absorbed % 8;
    ctx->state[lane] ^= (uint64_t)domain_sep << (8 * offset);

    /* XOR 0x80 at the last byte of the rate block. */
    lane = (rate - 1) / 8;
    offset = (rate - 1) % 8;
    ctx->state[lane] ^= (uint64_t)0x80 << (8 * offset);

    keccak_f1600(ctx->state);

    ctx->absorbed = 0;
    ctx->squeezing = 1;
}

/**
 * @brief Squeeze output bytes from the Keccak sponge.
 *
 * @param[in,out] ctx     Keccak state (must be finalized).
 * @param[out]    out     Output buffer.
 * @param[in]     outlen  Number of bytes to squeeze.
 */
static void keccak_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen) {
    size_t rate = ctx->rate;
    size_t offset = ctx->absorbed;

    while (outlen > 0) {
        if (offset == rate) {
            keccak_f1600(ctx->state);
            offset = 0;
        }

        size_t avail = rate - offset;
        size_t chunk = (outlen < avail) ? outlen : avail;

        /* Extract bytes from state at current offset. */
        {
            size_t i;
            for (i = 0; i < chunk; i++) {
                size_t pos = offset + i;
                size_t lane = pos / 8;
                size_t shift = pos % 8;
                out[i] = (uint8_t)(ctx->state[lane] >> (8 * shift));
            }
        }

        offset += chunk;
        out += chunk;
        outlen -= chunk;
    }

    ctx->absorbed = offset;
}

/**
 * @brief Generic sponge hash: absorb all input, finalize, squeeze output.
 *
 * @param[out] out         Output buffer.
 * @param[in]  outlen      Number of output bytes.
 * @param[in]  in          Input message.
 * @param[in]  inlen       Input length in bytes.
 * @param[in]  domain_sep  Domain separation byte.
 * @param[in]  rate        Sponge rate in bytes.
 */
static void keccak_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                        uint8_t domain_sep, size_t rate) {
    rivide_keccak_state_t ctx;

    keccak_init(&ctx, rate);
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, domain_sep);
    keccak_squeeze(&ctx, out, outlen);
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
    keccak_init(ctx, SHAKE128_RATE);
}

void rivide_shake256_init(rivide_keccak_state_t *ctx) {
    keccak_init(ctx, SHAKE256_RATE);
}

void rivide_shake_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen) {
    keccak_absorb(ctx, in, inlen);
}

void rivide_shake_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) {
        keccak_finalize(ctx, SHAKE_DOMAIN_SEP);
    }
    keccak_squeeze(ctx, out, outlen);
}
