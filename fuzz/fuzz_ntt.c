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
 * @file fuzz_ntt.c
 * @brief LLVM libFuzzer target for NTT/INTT transformations, base multiplications,
 * modular reductions, and SIMD polynomial vector arithmetic.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rivide/internal/dsa_ntt.h"
#include "rivide/internal/dsa_poly.h"
#include "rivide/internal/dsa_reduce.h"
#include "rivide/internal/dsa_sampling.h"
#include "rivide/internal/kem_ntt.h"
#include "rivide/internal/kem_packing.h"
#include "rivide/internal/kem_poly.h"
#include "rivide/internal/kem_reduce.h"
#include "rivide/pqc/ntt_simd.h"
#include "rivide/rivide.h"
#include "rivide/utils/mem.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        rivide_init();
        initialized = 1;
    }

    /* We need at least 512 bytes to fill a 256-coefficient polynomial of int16_t */
    if (size < 512) {
        return 0;
    }

    /* 1. ML-KEM NTT / INTT & Reductions (q = 3329) */
    poly_t kem_p1, kem_p2, kem_out;
    unsigned int i;

    for (i = 0; i < KEM_N; i++) {
        uint16_t val = (uint16_t)((uint16_t)data[2 * i] | ((uint16_t)data[2 * i + 1] << 8));
        kem_p1.coeffs[i] = (int16_t)(val % KEM_Q);
        kem_p2.coeffs[i] = (int16_t)((val ^ 0x55AA) % KEM_Q);
    }

    poly_ntt(&kem_p1);
    poly_ntt(&kem_p2);
    poly_basemul(&kem_out, &kem_p1, &kem_p2);
    poly_invntt(&kem_out);
    poly_reduce(&kem_out);
    poly_csubq(&kem_out);

    poly_add(&kem_p1, &kem_p1, &kem_p2);
    poly_sub(&kem_p1, &kem_p1, &kem_p2);

    /* 2. ML-DSA NTT / INTT & Pointwise Arithmetic (q = 8380417) */
    if (size >= 1024) {
        dsa_poly_t dsa_p1, dsa_p2, dsa_out;
        for (i = 0; i < DSA_N; i++) {
            uint32_t val = (uint32_t)data[4 * i] | ((uint32_t)data[4 * i + 1] << 8) |
                           ((uint32_t)data[4 * i + 2] << 16) | ((uint32_t)data[4 * i + 3] << 24);
            dsa_p1.coeffs[i] = (int32_t)(val % (uint32_t)DSA_Q);
            dsa_p2.coeffs[i] = (int32_t)((val ^ 0x12345678) % (uint32_t)DSA_Q);
        }

        dsa_poly_ntt(&dsa_p1);
        dsa_poly_ntt(&dsa_p2);
        dsa_poly_pointwise(&dsa_out, &dsa_p1, &dsa_p2);
        dsa_poly_invntt(&dsa_out);
        for (i = 0; i < DSA_N; i++) {
            dsa_out.coeffs[i] = dsa_caddq(dsa_out.coeffs[i]);
        }

        dsa_poly_tomont(&dsa_p1);
        dsa_poly_add(&dsa_p1, &dsa_p1, &dsa_p2);
        dsa_poly_sub(&dsa_p1, &dsa_p1, &dsa_p2);
        dsa_poly_reduce(&dsa_p1);

        rivide_cleanse(&dsa_p1, sizeof(dsa_p1));
        rivide_cleanse(&dsa_p2, sizeof(dsa_p2));
        rivide_cleanse(&dsa_out, sizeof(dsa_out));
    }

    /* 3. SIMD Vector Acceleration */
    int16_t simd_out[256];
    rivide_simd_poly_add_reduce(simd_out, kem_p1.coeffs, kem_p2.coeffs, KEM_Q);
    rivide_simd_poly_sub_reduce(simd_out, kem_p1.coeffs, kem_p2.coeffs, KEM_Q);
    rivide_cleanse(simd_out, sizeof(simd_out));

    rivide_cleanse(&kem_p1, sizeof(kem_p1));
    rivide_cleanse(&kem_p2, sizeof(kem_p2));
    rivide_cleanse(&kem_out, sizeof(kem_out));

    return 0;
}
