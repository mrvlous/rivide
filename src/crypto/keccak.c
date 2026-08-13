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
 * @file keccak.c
 * @brief Keccak-f[1600] 24-round permutation and sponge absorb/squeeze implementation.
 *
 * Implements the 1600-bit state permutation and the multi-rate sponge construction
 * conforming to NIST FIPS 202 specifications.
 */

#include "rivide/crypto/keccak.h"

#include "rivide/rivide_config.h"
#include "rivide/utils/mem.h"

/**
 * @brief Bitwise 64-bit rotate left.
 *
 * @param[in] x Value to rotate.
 * @param[in] n Number of bits to rotate.
 * @return Rotated value.
 */
static uint64_t rotl64(uint64_t x, unsigned int n) {
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

/** @brief Keccak round constants for the iota (ι) step mapping. */
static const uint64_t keccak_rc[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808A),
    UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008A),
    UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B), UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A), UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)};

/**
 * @brief Execute the Keccak-f[1600] 24-round permutation on a 25-lane state array.
 *
 * @param[in,out] s 25-lane 64-bit integer state array (1600 bits).
 */
static const unsigned int rho_offsets[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                                             25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};

/**
 * @brief Execute the Keccak-f[1600] 24-round permutation on a 25-lane state array.
 *
 * @param[in,out] s 25-lane 64-bit integer state array (1600 bits).
 */
void rivide_keccak_f1600(uint64_t s[25]) {
    int round;
    uint64_t C[5], D[5], B[25];
    int x, y;

    for (round = 0; round < 24; round++) {
        /* Theta step: compute column parities and XOR with neighbors. */
        for (x = 0; x < 5; x++) {
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for (x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                s[5 * y + x] ^= D[x];
            }
        }

        /* Rho and Pi steps: rotate each lane and rearrange positions. */
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                int idx = 5 * y + x;
                B[5 * ((2 * x + 3 * y) % 5) + y] = rotl64(s[idx], rho_offsets[idx]);
            }
        }

        /* Chi step: non-linear mixing within each row. */
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                s[5 * y + x] = B[5 * y + x] ^ (~B[5 * y + (x + 1) % 5] & B[5 * y + (x + 2) % 5]);
            }
        }

        /* Iota step: break symmetry with round constant. */
        s[0] ^= keccak_rc[round];
    }
}

/**
 * @brief Initialize a Keccak sponge state with a specified rate.
 *
 * @param[out] ctx  Pointer to the Keccak state context.
 * @param[in]  rate Sponge block rate in bytes.
 */
void rivide_keccak_init(rivide_keccak_state_t *ctx, size_t rate) {
    size_t i;
    for (i = 0; i < 25; i++) {
        ctx->state[i] = 0;
    }
    ctx->absorbed = 0;
    ctx->rate = rate;
    ctx->squeezing = 0;
}

/**
 * @brief Absorb input message bytes into the Keccak sponge.
 *
 * @param[in,out] ctx   Pointer to the Keccak state context.
 * @param[in]     in    Input message buffer.
 * @param[in]     inlen Length of input message in bytes.
 */
void rivide_keccak_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen) {
    size_t rate = ctx->rate;
    size_t absorbed = ctx->absorbed;

    while (inlen > 0) {
        size_t avail = rate - absorbed;
        size_t chunk = (inlen < avail) ? inlen : avail;

        if (in) {
            size_t i;
            for (i = 0; i < chunk; i++) {
                size_t pos = absorbed + i;
                size_t lane = pos / 8;
                size_t offset = pos % 8;
                ctx->state[lane] ^= (uint64_t)in[i] << (8 * offset);
            }
        }

        absorbed += chunk;
        if (in) {
            in += chunk;
        }
        inlen -= chunk;

        if (absorbed == rate) {
            rivide_keccak_f1600(ctx->state);
            absorbed = 0;
        }
    }

    ctx->absorbed = absorbed;
}

/**
 * @brief Finalize the absorb phase with domain separation and 10*1 padding.
 *
 * @param[in,out] ctx        Pointer to the Keccak state context.
 * @param[in]     domain_sep Domain separation byte (0x06 for SHA-3, 0x1F for SHAKE).
 */
void rivide_keccak_finalize(rivide_keccak_state_t *ctx, uint8_t domain_sep) {
    size_t absorbed = ctx->absorbed;
    size_t rate = ctx->rate;
    size_t lane, offset;

    lane = absorbed / 8;
    offset = absorbed % 8;
    ctx->state[lane] ^= (uint64_t)domain_sep << (8 * offset);

    lane = (rate - 1) / 8;
    offset = (rate - 1) % 8;
    ctx->state[lane] ^= (uint64_t)0x80 << (8 * offset);

    rivide_keccak_f1600(ctx->state);

    ctx->absorbed = 0;
    ctx->squeezing = 1;
}

/**
 * @brief Squeeze output bytes from the Keccak sponge context.
 *
 * @param[in,out] ctx    Pointer to the Keccak state context.
 * @param[out]    out    Output byte buffer.
 * @param[in]     outlen Number of bytes to squeeze.
 */
void rivide_keccak_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen) {
    size_t rate = ctx->rate;
    size_t offset = ctx->absorbed;

    while (outlen > 0) {
        if (offset == rate) {
            rivide_keccak_f1600(ctx->state);
            offset = 0;
        }

        size_t avail = rate - offset;
        size_t chunk = (outlen < avail) ? outlen : avail;

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
