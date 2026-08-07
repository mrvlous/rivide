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
 * @file sha3.h
 * @brief SHA-3 hash functions and SHAKE extendable-output functions.
 *
 * Implements the NIST FIPS 202 family: SHA3-256, SHA3-512, SHAKE-128, and
 * SHAKE-256. All functions are built on the Keccak-f[1600] permutation using
 * the sponge construction.
 *
 * Both one-shot convenience functions and incremental (init/absorb/squeeze)
 * APIs are provided for maximum flexibility. The incremental API allows
 * processing data in arbitrary-sized chunks without buffering the entire
 * message in memory.
 */

#ifndef RIVIDE_CRYPTO_SHA3_H
#define RIVIDE_CRYPTO_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief SHA3-256 output length in bytes. */
#define RIVIDE_SHA3_256_BYTES 32

/** @brief SHA3-512 output length in bytes. */
#define RIVIDE_SHA3_512_BYTES 64

/** @brief Keccak state size in bytes (1600 bits). */
#define RIVIDE_KECCAK_STATE_BYTES 200

/**
 * @brief Keccak sponge state structure.
 *
 * Used by all SHA-3 and SHAKE functions. The state consists of a 5x5 matrix
 * of 64-bit lanes (200 bytes total), along with bookkeeping fields for the
 * sponge construction. Callers should treat this as an opaque structure.
 */
typedef struct rivide_keccak_state {
    /** @brief The 1600-bit Keccak permutation state as 25 lanes. */
    uint64_t state[25];

    /** @brief Number of bytes currently buffered (not yet absorbed). */
    size_t absorbed;

    /** @brief Sponge rate in bytes (determines block size). */
    size_t rate;

    /** @brief Set to 1 once the sponge has been finalized for squeezing. */
    int squeezing;
} rivide_keccak_state_t;

/**
 * @brief Compute SHA3-256 hash of a message.
 *
 * @param[out] out     Output buffer, must be at least @ref RIVIDE_SHA3_256_BYTES bytes.
 * @param[in]  in      Input message.
 * @param[in]  inlen   Length of the input message in bytes.
 */
void rivide_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen);

/**
 * @brief Compute SHA3-512 hash of a message.
 *
 * @param[out] out     Output buffer, must be at least @ref RIVIDE_SHA3_512_BYTES bytes.
 * @param[in]  in      Input message.
 * @param[in]  inlen   Length of the input message in bytes.
 */
void rivide_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);

/**
 * @brief Compute SHAKE-128 XOF output.
 *
 * @param[out] out     Output buffer.
 * @param[in]  outlen  Number of output bytes to produce.
 * @param[in]  in      Input message (seed).
 * @param[in]  inlen   Length of the input message in bytes.
 */
void rivide_shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/**
 * @brief Compute SHAKE-256 XOF output.
 *
 * @param[out] out     Output buffer.
 * @param[in]  outlen  Number of output bytes to produce.
 * @param[in]  in      Input message (seed).
 * @param[in]  inlen   Length of the input message in bytes.
 */
void rivide_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/**
 * @brief Initialize a SHAKE-128 XOF context for incremental use.
 *
 * @param[out] ctx  Keccak state to initialize.
 */
void rivide_shake128_init(rivide_keccak_state_t *ctx);

/**
 * @brief Initialize a SHAKE-256 XOF context for incremental use.
 *
 * @param[out] ctx  Keccak state to initialize.
 */
void rivide_shake256_init(rivide_keccak_state_t *ctx);

/**
 * @brief Absorb input data into a SHAKE context.
 *
 * May be called repeatedly to process data in chunks. Must not be called
 * after @ref rivide_shake_squeeze has been invoked on the same context.
 *
 * @param[in,out] ctx    Keccak state (must have been initialized).
 * @param[in]     in     Input data to absorb.
 * @param[in]     inlen  Length of the input data in bytes.
 */
void rivide_shake_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen);

/**
 * @brief Squeeze output bytes from a SHAKE context.
 *
 * On the first call, this finalizes the absorb phase by applying padding
 * and performing the final permutation. Subsequent calls continue squeezing
 * additional output bytes from the same state.
 *
 * @param[in,out] ctx     Keccak state.
 * @param[out]    out     Output buffer.
 * @param[in]     outlen  Number of bytes to squeeze.
 */
void rivide_shake_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_CRYPTO_SHA3_H */
