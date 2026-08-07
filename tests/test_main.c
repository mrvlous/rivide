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
 * @brief Minimal test harness and runner for the Rivide test suite.
 *
 * Provides lightweight assertion macros and a test runner that does not
 * depend on any external test framework, consistent with the zero-dependency
 * design philosophy.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

/** @brief Global test counters. */
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

/**
 * @brief Assert that a status code equals RIVIDE_SUCCESS.
 */
#define ASSERT_OK(expr)                                                            \
    do {                                                                           \
        rivide_status_t _status = (expr);                                          \
        if (_status != RIVIDE_SUCCESS) {                                           \
            fprintf(stderr, "  FAIL: %s returned %s (%d) at %s:%d\n", #expr,       \
                    rivide_status_str(_status), (int)_status, __FILE__, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

/**
 * @brief Assert that two integer values are equal.
 */
#define ASSERT_EQ(a, b)                                                                           \
    do {                                                                                          \
        if ((a) != (b)) {                                                                         \
            fprintf(stderr, "  FAIL: %s != %s (%d != %d) at %s:%d\n", #a, #b, (int)(a), (int)(b), \
                    __FILE__, __LINE__);                                                          \
            return 1;                                                                             \
        }                                                                                         \
    } while (0)

/**
 * @brief Assert that two byte buffers are equal.
 */
#define ASSERT_MEM_EQ(a, b, len)                                                                 \
    do {                                                                                         \
        if (memcmp((a), (b), (len)) != 0) {                                                      \
            fprintf(stderr, "  FAIL: %s != %s (memory) at %s:%d\n", #a, #b, __FILE__, __LINE__); \
            return 1;                                                                            \
        }                                                                                        \
    } while (0)

/**
 * @brief Assert that two byte buffers are NOT equal.
 */
#define ASSERT_MEM_NE(a, b, len)                             \
    do {                                                     \
        if (memcmp((a), (b), (len)) == 0) {                  \
            fprintf(stderr,                                  \
                    "  FAIL: %s == %s (expected different) " \
                    "at %s:%d\n",                            \
                    #a, #b, __FILE__, __LINE__);             \
            return 1;                                        \
        }                                                    \
    } while (0)

/**
 * @brief Assert that a status code indicates failure.
 */
#define ASSERT_FAIL(expr)                                                                \
    do {                                                                                 \
        rivide_status_t _status = (expr);                                                \
        if (_status == RIVIDE_SUCCESS) {                                                 \
            fprintf(stderr, "  FAIL: %s should have failed at %s:%d\n", #expr, __FILE__, \
                    __LINE__);                                                           \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

/**
 * @brief Run a test function and track results.
 */
#define RUN_TEST(test_func)                               \
    do {                                                  \
        g_tests_run++;                                    \
        printf("  [%d] %-50s ", g_tests_run, #test_func); \
        fflush(stdout);                                   \
        if (test_func() == 0) {                           \
            printf("PASS\n");                             \
            g_tests_passed++;                             \
        } else {                                          \
            printf("FAIL\n");                             \
            g_tests_failed++;                             \
        }                                                 \
    } while (0)

/* External test suite declarations. */
extern int test_ml_kem_768_roundtrip(void);
extern int test_ml_kem_768_invalid_ct(void);
extern int test_ml_kem_1024_roundtrip(void);
extern int test_ml_dsa_65_roundtrip(void);
extern int test_ml_dsa_65_tampered_msg(void);
extern int test_ml_dsa_87_roundtrip(void);

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

    printf("\nResults: %d/%d passed, %d failed\n", g_tests_passed, g_tests_run, g_tests_failed);

    return (g_tests_failed > 0) ? 1 : 0;
}
