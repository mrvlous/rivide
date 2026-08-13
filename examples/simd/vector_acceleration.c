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
 * @file vector_acceleration.c
 * @brief SIMD hardware acceleration feature reporting and vector polynomial operations.
 *
 * Queries detected CPU SIMD extensions (AVX2 / ARM NEON / AES-NI / ARM Crypto)
 * and executes vectorized polynomial arithmetic.
 */

#include <stdio.h>

#include "rivide/pqc/ntt_simd.h"
#include "rivide/rivide.h"

int main(void) {
    uint32_t features;
    int16_t poly_a[256];
    int16_t poly_b[256];
    int16_t poly_res[256];
    rivide_status_t status;
    int i;

    printf("Rivide Hardware SIMD Acceleration & Feature Detection\n");

    /* Initialize CPU feature detection */
    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    features = rivide_get_cpu_features();

    printf("Detected Hardware Acceleration Capabilities:\n");
    printf(" - AES-NI Hardware Acceleration:   %s\n", (features & 0x01) ? "YES" : "NO");
    printf(" - ARM Crypto Extensions:          %s\n", (features & 0x02) ? "YES" : "NO");
    printf(" - AVX2 256-bit SIMD Vectorizing:  %s\n", (features & 0x04) ? "YES" : "NO");
    printf(" - ARM NEON 128-bit SIMD Vector:   %s\n", (features & 0x08) ? "YES" : "NO");

    /* Populate test polynomial vectors */
    for (i = 0; i < 256; i++) {
        poly_a[i] = (int16_t)(i * 2);
        poly_b[i] = (int16_t)(i * 3);
    }

    /* Perform vectorized polynomial addition */
    printf("\nExecuting SIMD vector polynomial addition...\n");
    rivide_simd_poly_add_reduce(poly_res, poly_a, poly_b, 3329);

    printf("Sample Results (Coefficients 0..3):\n");
    for (i = 0; i < 4; i++) {
        printf("  Coeff[%d]: %d + %d = %d\n", i, poly_a[i], poly_b[i], poly_res[i]);
    }

    printf("\n[SUCCESS] SIMD vector operations completed successfully.\n");
    return 0;
}
