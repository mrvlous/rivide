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
 * @file fuzz_sha3.c
 * @brief LLVM libFuzzer target for SHA-3 hashing and SHAKE incremental extendable-output functions.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rivide/crypto/sha3.h"
#include "rivide/rivide.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t out32[32];
    uint8_t out64[64];

    /* Direct one-shot hashing */
    rivide_sha3_256(out32, data, size);
    rivide_sha3_512(out64, data, size);
    rivide_shake128(out32, sizeof(out32), data, size);
    rivide_shake256(out64, sizeof(out64), data, size);

    /* Incremental SHAKE-256 absorption and squeezing */
    rivide_keccak_state_t ctx256;
    rivide_shake256_init(&ctx256);
    if (size > 0) {
        size_t half = size / 2;
        rivide_shake_absorb(&ctx256, data, half);
        rivide_shake_absorb(&ctx256, data + half, size - half);
    }
    rivide_shake_squeeze(&ctx256, out64, sizeof(out64));
    rivide_cleanse(&ctx256, sizeof(ctx256));

    /* Incremental SHAKE-128 absorption and squeezing */
    rivide_keccak_state_t ctx128;
    rivide_shake128_init(&ctx128);
    if (size > 0) {
        rivide_shake_absorb(&ctx128, data, size);
    }
    rivide_shake_squeeze(&ctx128, out32, sizeof(out32));
    rivide_cleanse(&ctx128, sizeof(ctx128));

    rivide_cleanse(out32, sizeof(out32));
    rivide_cleanse(out64, sizeof(out64));

    return 0;
}
