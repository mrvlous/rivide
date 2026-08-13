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
 * @file test_harness.h
 * @brief Common test macros, assertions, and counters for the Rivide test suite.
 */

#ifndef RIVIDE_TEST_HARNESS_H
#define RIVIDE_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

#define ASSERT_OK(expr)                                                            \
    do {                                                                           \
        rivide_status_t _status = (expr);                                          \
        if (_status != RIVIDE_SUCCESS) {                                           \
            fprintf(stderr, "  FAIL: %s returned %s (%d) at %s:%d\n", #expr,       \
                    rivide_status_str(_status), (int)_status, __FILE__, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

#define ASSERT_EQ(a, b)                                                                           \
    do {                                                                                          \
        if ((a) != (b)) {                                                                         \
            fprintf(stderr, "  FAIL: %s != %s (%d != %d) at %s:%d\n", #a, #b, (int)(a), (int)(b), \
                    __FILE__, __LINE__);                                                          \
            return 1;                                                                             \
        }                                                                                         \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len)                                                                 \
    do {                                                                                         \
        if (memcmp((a), (b), (len)) != 0) {                                                      \
            fprintf(stderr, "  FAIL: %s != %s (memory) at %s:%d\n", #a, #b, __FILE__, __LINE__); \
            return 1;                                                                            \
        }                                                                                        \
    } while (0)

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

#define ASSERT_FAIL(expr)                                                                \
    do {                                                                                 \
        rivide_status_t _status = (expr);                                                \
        if (_status == RIVIDE_SUCCESS) {                                                 \
            fprintf(stderr, "  FAIL: %s should have failed at %s:%d\n", #expr, __FILE__, \
                    __LINE__);                                                           \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

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

#endif /* RIVIDE_TEST_HARNESS_H */
