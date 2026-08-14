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
 * @file test_kat_harness.h
 * @brief Known Answer Test (KAT) test harness and vector validation utilities.
 */

#ifndef RIVIDE_TEST_KAT_HARNESS_H
#define RIVIDE_TEST_KAT_HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

extern int g_kat_run;
extern int g_kat_passed;
extern int g_kat_failed;

#define RUN_KAT(test_fn)                              \
    do {                                              \
        g_kat_run++;                                  \
        printf("  [%d] %-48s ", g_kat_run, #test_fn); \
        fflush(stdout);                               \
        if (test_fn() == 0) {                         \
            g_kat_passed++;                           \
            printf("PASS\n");                         \
        } else {                                      \
            g_kat_failed++;                           \
            printf("FAIL\n");                         \
        }                                             \
    } while (0)

#define KAT_ASSERT(cond)                                                               \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("\n    KAT FAILURE: %s at %s:%d\n    ", #cond, __FILE__, __LINE__); \
            return 1;                                                                  \
        }                                                                              \
    } while (0)

#define KAT_ASSERT_BYTES_EQ(a, b, len)                                                        \
    do {                                                                                      \
        size_t _i;                                                                            \
        const uint8_t *_a = (const uint8_t *)(a);                                             \
        const uint8_t *_b = (const uint8_t *)(b);                                             \
        for (_i = 0; _i < (len); _i++) {                                                      \
            if (_a[_i] != _b[_i]) {                                                           \
                printf("\n    KAT BYTE MISMATCH at byte %zu: expected 0x%02x, got 0x%02x at " \
                       "%s:%d\n    ",                                                         \
                       _i, _b[_i], _a[_i], __FILE__, __LINE__);                               \
                return 1;                                                                     \
            }                                                                                 \
        }                                                                                     \
    } while (0)

/**
 * @brief Helper to convert hexadecimal string to byte array.
 *
 * @param[out] out Output byte buffer.
 * @param[in]  hex Hexadecimal string.
 * @param[in]  len Expected number of bytes.
 * @return 0 on success, non-zero on parsing error.
 */
static inline int kat_hex_to_bytes(uint8_t *out, const char *hex, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        char c1 = hex[2 * i];
        char c2 = hex[2 * i + 1];
        int v1, v2;

        if (c1 >= '0' && c1 <= '9') {
            v1 = c1 - '0';
        } else if (c1 >= 'a' && c1 <= 'f') {
            v1 = c1 - 'a' + 10;
        } else if (c1 >= 'A' && c1 <= 'F') {
            v1 = c1 - 'A' + 10;
        } else {
            return 1;
        }

        if (c2 >= '0' && c2 <= '9') {
            v2 = c2 - '0';
        } else if (c2 >= 'a' && c2 <= 'f') {
            v2 = c2 - 'a' + 10;
        } else if (c2 >= 'A' && c2 <= 'F') {
            v2 = c2 - 'A' + 10;
        } else {
            return 1;
        }

        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    return 0;
}

#endif /* RIVIDE_TEST_KAT_HARNESS_H */
