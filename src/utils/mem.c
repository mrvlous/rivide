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
    return (int)((diff | (0u - diff)) >> 31);
}

void rivide_ct_select(void *dst, const void *src_a, const void *src_b, size_t len, int selector) {
    const unsigned char *a = (const unsigned char *)src_a;
    const unsigned char *b = (const unsigned char *)src_b;
    unsigned char *d = (unsigned char *)dst;
    unsigned char mask;
    size_t i;

    /*
     * Convert selector to an all-zero or all-one byte mask without branching.
     * If selector is 0, mask is 0x00 (select src_a).
     * If selector is non-zero, mask is 0xFF (select src_b).
     */
    mask = (unsigned char)(-(selector != 0));

    for (i = 0; i < len; i++) {
        d[i] = (unsigned char)(a[i] ^ (mask & (a[i] ^ b[i])));
    }
}
