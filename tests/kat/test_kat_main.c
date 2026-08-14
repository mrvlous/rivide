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
 * @file test_kat_main.c
 * @brief Main driver for Rivide NIST Known Answer Tests (KAT) suite.
 */

#include "test_kat_harness.h"

int g_kat_run = 0;
int g_kat_passed = 0;
int g_kat_failed = 0;

/* External test declarations from KAT sub-modules. */
extern int kat_sha3_256_nist_vectors(void);
extern int kat_sha3_512_nist_vectors(void);
extern int kat_shake128_nist_vectors(void);
extern int kat_shake256_nist_vectors(void);

extern int kat_ml_kem_768_functional_vector(void);
extern int kat_ml_kem_1024_functional_vector(void);

extern int kat_ml_dsa_65_functional_vector(void);
extern int kat_ml_dsa_87_functional_vector(void);

int main(void) {
    rivide_status_t status;

    printf("Rivide NIST Known Answer Test (KAT) Suite v%s\n\n", rivide_version_string());

    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "FATAL: Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    printf("NIST FIPS 202 SHA-3 / SHAKE KAT Vectors:\n");
    RUN_KAT(kat_sha3_256_nist_vectors);
    RUN_KAT(kat_sha3_512_nist_vectors);
    RUN_KAT(kat_shake128_nist_vectors);
    RUN_KAT(kat_shake256_nist_vectors);

    printf("\nNIST FIPS 203 ML-KEM KAT Vectors:\n");
    RUN_KAT(kat_ml_kem_768_functional_vector);
    RUN_KAT(kat_ml_kem_1024_functional_vector);

    printf("\nNIST FIPS 204 ML-DSA KAT Vectors:\n");
    RUN_KAT(kat_ml_dsa_65_functional_vector);
    RUN_KAT(kat_ml_dsa_87_functional_vector);

    printf("\nKAT Results: %d/%d passed, %d failed\n", g_kat_passed, g_kat_run, g_kat_failed);

    return (g_kat_failed > 0) ? 1 : 0;
}
