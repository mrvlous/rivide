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
 * @file ghash.h
 * @brief GHASH multiplication in GF(2^128) interface.
 */

#ifndef RIVIDE_CRYPTO_GHASH_H
#define RIVIDE_CRYPTO_GHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief GHASH multiplication in GF(2^128).
 *
 * Multiplies two 128-bit values in GF(2^128) mod (x^128 + x^7 + x^2 + x + 1).
 */
void rivide_ghash_mult(uint8_t x[16], const uint8_t y[16]);

/**
 * @brief GHASH update over arbitrary byte sequences.
 */
void rivide_ghash_update(const uint8_t h[16], const uint8_t *data, size_t len, uint8_t tag[16]);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_CRYPTO_GHASH_H */
