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
 * @file mem.h
 * @brief Constant-time memory comparison and secure memory cleansing utilities.
 *
 * These routines are designed to resist side-channel timing attacks by ensuring
 * that execution time does not depend on secret data values. The cleanse
 * function additionally prevents the compiler from eliding the zeroization
 * through dead-store elimination.
 */

#ifndef RIVIDE_UTILS_MEM_H
#define RIVIDE_UTILS_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely erase sensitive data from memory.
 *
 * Overwrites @p len bytes starting at @p ptr with zeroes, using a volatile
 * pointer and compiler memory barrier to guarantee that the write is not
 * optimized away. This function should be called on any buffer containing
 * secret key material before the buffer goes out of scope.
 *
 * @param[out] ptr  Pointer to the memory region to cleanse. May be NULL
 *                  only if @p len is 0.
 * @param[in]  len  Number of bytes to zero.
 */
void rivide_cleanse(void *ptr, size_t len);

/**
 * @brief Constant-time memory comparison.
 *
 * Compares @p len bytes of memory at @p a and @p b. The execution time is
 * independent of the contents of the buffers, making this suitable for
 * comparing MACs, hashes, and other secret-derived values.
 *
 * @param[in] a    Pointer to the first buffer.
 * @param[in] b    Pointer to the second buffer.
 * @param[in] len  Number of bytes to compare.
 *
 * @return 0 if the buffers are identical, non-zero otherwise. The exact
 *         non-zero value is unspecified and must not be relied upon.
 */
int rivide_ct_memcmp(const void *a, const void *b, size_t len);

/**
 * @brief Constant-time conditional select.
 *
 * Copies @p len bytes from @p src_a (if @p selector is 0) or @p src_b
 * (if @p selector is non-zero) into @p dst, without branching on the
 * selector value.
 *
 * @param[out] dst       Destination buffer.
 * @param[in]  src_a     Source buffer selected when @p selector is 0.
 * @param[in]  src_b     Source buffer selected when @p selector is non-zero.
 * @param[in]  len       Number of bytes to copy.
 * @param[in]  selector  Selection flag (0 or non-zero).
 */
void rivide_ct_select(void *dst, const void *src_a, const void *src_b, size_t len, int selector);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_UTILS_MEM_H */
