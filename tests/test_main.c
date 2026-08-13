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
 * @file test_main.c
 * @brief Test suite entry point and test runner for Rivide.
 */

#include "test_harness.h"

int g_tests_run = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

/* External test declarations from sub-modules. */
extern int test_ml_kem_768_roundtrip(void);
extern int test_ml_kem_768_invalid_ct(void);
extern int test_ml_kem_1024_roundtrip(void);

extern int test_ml_dsa_65_roundtrip(void);
extern int test_ml_dsa_65_tampered_msg(void);
extern int test_ml_dsa_87_roundtrip(void);
extern int test_ml_dsa_65_siglen_validation(void);
extern int test_ml_dsa_87_siglen_validation(void);
extern int test_ml_dsa_boundary_fuzz(void);

extern int test_simd_poly_add_reduce(void);
extern int test_simd_poly_sub_reduce(void);
extern int test_ml_kem_ntt_invertibility(void);
extern int test_ml_dsa_ntt_invertibility(void);
extern int test_modular_reductions(void);

extern int test_sha3_256_empty(void);
extern int test_shake128_incremental(void);

extern int test_aes128_gcm_roundtrip(void);
extern int test_aes256_gcm_invalid_tag(void);

extern int test_ct_memcmp(void);
extern int test_ct_select(void);

int main(void) {
    rivide_status_t ret;

    printf("Rivide Test Suite v%s\n\n", rivide_version_string());

    ret = rivide_init();
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(ret));
        return 1;
    }

    printf("ML-KEM Tests:\n");
    RUN_TEST(test_ml_kem_768_roundtrip);
    RUN_TEST(test_ml_kem_768_invalid_ct);
    RUN_TEST(test_ml_kem_1024_roundtrip);

    printf("\nML-DSA Tests:\n");
    RUN_TEST(test_ml_dsa_65_roundtrip);
    RUN_TEST(test_ml_dsa_65_tampered_msg);
    RUN_TEST(test_ml_dsa_87_roundtrip);
    RUN_TEST(test_ml_dsa_65_siglen_validation);
    RUN_TEST(test_ml_dsa_87_siglen_validation);
    RUN_TEST(test_ml_dsa_boundary_fuzz);

    printf("\nSIMD & NTT Arithmetic Tests:\n");
    RUN_TEST(test_simd_poly_add_reduce);
    RUN_TEST(test_simd_poly_sub_reduce);
    RUN_TEST(test_ml_kem_ntt_invertibility);
    RUN_TEST(test_ml_dsa_ntt_invertibility);
    RUN_TEST(test_modular_reductions);

    printf("\nCrypto Primitives Tests:\n");
    RUN_TEST(test_sha3_256_empty);
    RUN_TEST(test_shake128_incremental);
    RUN_TEST(test_aes128_gcm_roundtrip);
    RUN_TEST(test_aes256_gcm_invalid_tag);

    printf("\nUtility Tests:\n");
    RUN_TEST(test_ct_memcmp);
    RUN_TEST(test_ct_select);

    printf("\nResults: %d/%d passed, %d failed\n", g_tests_passed, g_tests_run, g_tests_failed);

    return (g_tests_failed > 0) ? 1 : 0;
}
