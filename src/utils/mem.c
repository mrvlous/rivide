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
 * @file mem.c
 * @brief Implementation of constant-time memory operations and secure cleansing.
 */

#include "rivide/utils/mem.h"

void rivide_cleanse(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;

    for (i = 0; i < len; i++) {
        p[i] = 0;
    }

    /*
     * Compiler memory barrier: ensures the compiler does not reorder or
     * eliminate the preceding volatile writes, even if the buffer appears
     * dead after this call.
     */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

int rivide_ct_memcmp(const void *a, const void *b, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (!a || !b) {
        return (a == b) ? 0 : 1;
    }

    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned int diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= (unsigned int)(pa[i] ^ pb[i]);
    }

    /*
     * Collapse the accumulated XOR difference into a single 0-or-1 result.
     * Returns 0 if buffers are equal, 1 if they differ.
     */
    return (int)((diff | (0u - diff)) >> 31u);
}

#if defined(__GNUC__) || defined(__clang__)
#define RIVIDE_CONSTTIME_BARRIER(var) __asm__ volatile("" : "+r"(var))
#elif defined(_MSC_VER)
#define RIVIDE_CONSTTIME_BARRIER(var) _ReadWriteBarrier()
#else
#define RIVIDE_CONSTTIME_BARRIER(var) ((void)0)
#endif

void rivide_ct_select(void *dst, const void *src_a, const void *src_b, size_t len, int selector) {
    if (!dst || !src_a || !src_b || len == 0) {
        return;
    }

    const unsigned char *a = (const unsigned char *)src_a;
    const unsigned char *b = (const unsigned char *)src_b;
    unsigned char *d = (unsigned char *)dst;
    uint32_t sel = (uint32_t)selector;
    uint32_t is_nonzero = (sel | (0u - sel)) >> 31u;
    unsigned int mask = (0u - is_nonzero) & 0xFFu;
    size_t i;

    /*
     * Optimization barrier: ensures compiler does not pattern-match
     * the mask into conditional branches or conditional move instructions.
     */
    RIVIDE_CONSTTIME_BARRIER(mask);

    for (i = 0; i < len; i++) {
        d[i] = (unsigned char)((unsigned int)a[i] ^
                               (mask & ((unsigned int)a[i] ^ (unsigned int)b[i])));
    }
}
