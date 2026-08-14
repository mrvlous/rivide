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
 * @file fuzz_ml_dsa_verify.c
 * @brief LLVM libFuzzer target for ML-DSA-65 and ML-DSA-87 signature verification.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rivide/rivide.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        rivide_init();
        initialized = 1;
    }

    /* Fuzz ML-DSA-65 Verification */
    if (size >= RIVIDE_ML_DSA_65_PK_BYTES + 32) {
        const uint8_t *pk = data;
        const uint8_t *sig_and_msg = data + RIVIDE_ML_DSA_65_PK_BYTES;
        size_t rem = size - RIVIDE_ML_DSA_65_PK_BYTES;
        size_t siglen = (rem < RIVIDE_ML_DSA_65_SIG_BYTES) ? rem : RIVIDE_ML_DSA_65_SIG_BYTES;
        const uint8_t *msg = sig_and_msg + siglen;
        size_t msglen = (rem > siglen) ? (rem - siglen) : 0;

        rivide_ml_dsa_65_verify(sig_and_msg, siglen, msg, msglen, pk);
    }

    /* Fuzz ML-DSA-87 Verification */
    if (size >= RIVIDE_ML_DSA_87_PK_BYTES + 32) {
        const uint8_t *pk = data;
        const uint8_t *sig_and_msg = data + RIVIDE_ML_DSA_87_PK_BYTES;
        size_t rem = size - RIVIDE_ML_DSA_87_PK_BYTES;
        size_t siglen = (rem < RIVIDE_ML_DSA_87_SIG_BYTES) ? rem : RIVIDE_ML_DSA_87_SIG_BYTES;
        const uint8_t *msg = sig_and_msg + siglen;
        size_t msglen = (rem > siglen) ? (rem - siglen) : 0;

        rivide_ml_dsa_87_verify(sig_and_msg, siglen, msg, msglen, pk);
    }

    return 0;
}
