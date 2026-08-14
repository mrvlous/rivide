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
 * @file fuzz_ml_kem_decaps.c
 * @brief LLVM libFuzzer target for ML-KEM-768 and ML-KEM-1024 decapsulation parsing.
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

    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];

    /* Fuzz ML-KEM-768 Decapsulation */
    if (size >= RIVIDE_ML_KEM_768_CT_BYTES + RIVIDE_ML_KEM_768_SK_BYTES) {
        const uint8_t *ct = data;
        const uint8_t *sk = data + RIVIDE_ML_KEM_768_CT_BYTES;
        rivide_ml_kem_768_decaps(ss, ct, sk);
    }

    /* Fuzz ML-KEM-1024 Decapsulation */
    if (size >= RIVIDE_ML_KEM_1024_CT_BYTES + RIVIDE_ML_KEM_1024_SK_BYTES) {
        const uint8_t *ct = data;
        const uint8_t *sk = data + RIVIDE_ML_KEM_1024_CT_BYTES;
        rivide_ml_kem_1024_decaps(ss, ct, sk);
    }

    return 0;
}
