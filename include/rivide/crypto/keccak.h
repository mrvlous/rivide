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
 * @file keccak.h
 * @brief Keccak-f[1600] permutation and core sponge engine.
 */

#ifndef RIVIDE_CRYPTO_KECCAK_H
#define RIVIDE_CRYPTO_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/crypto/sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Execute the Keccak-f[1600] permutation on a 25-lane state.
 */
void rivide_keccak_f1600(uint64_t state[25]);

/**
 * @brief Initialize a Keccak sponge state.
 */
void rivide_keccak_init(rivide_keccak_state_t *ctx, size_t rate);

/**
 * @brief Absorb input data into the Keccak sponge.
 */
void rivide_keccak_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen);

/**
 * @brief Finalize the absorb phase with domain separation and padding.
 */
void rivide_keccak_finalize(rivide_keccak_state_t *ctx, uint8_t domain_sep);

/**
 * @brief Squeeze output bytes from the Keccak sponge.
 */
void rivide_keccak_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_CRYPTO_KECCAK_H */
