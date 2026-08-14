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
 * @file bench_harness.h
 * @brief Benchmark timing harness, environment inspection, and result formatting.
 */

#ifndef RIVIDE_BENCH_HARNESS_H
#define RIVIDE_BENCH_HARNESS_H

#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#elif !defined(_WIN32) && !defined(_WIN64)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static inline double get_time_sec(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <time.h>
static inline double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
#endif

#include "rivide/rivide.h"

/**
 * @brief Get benchmark iteration count from environment or default.
 */
static inline int get_bench_iterations(int default_val) {
    const char *env = getenv("BENCH_ITERS");
    if (env) {
        int val = atoi(env);
        if (val > 0) {
            return val;
        }
    }
    return default_val;
}

/**
 * @brief Print benchmark environment header (CPU, Compiler, Version).
 */
static inline void print_bench_header(int iters) {
    uint32_t cpu_feats = rivide_get_cpu_features();

    printf("Rivide Post-Quantum Cryptography Benchmark Suite v%s\n\n", rivide_version_string());

    printf("Environment Information:\n");
#if defined(__clang__)
    printf("  Compiler             : Clang %s\n", __clang_version__);
#elif defined(__GNUC__)
    printf("  Compiler             : GCC %s\n", __VERSION__);
#elif defined(_MSC_VER)
    printf("  Compiler             : MSVC %d\n", _MSC_VER);
#else
    printf("  Compiler             : Standard C99 Compiler\n");
#endif

#if defined(NDEBUG)
    printf("  Build Configuration  : Release (-O3 / -DNDEBUG)\n");
#else
    printf("  Build Configuration  : Debug\n");
#endif
    printf("  Benchmark Iterations : %d runs per operation\n\n", iters);

    printf("Detected Hardware Acceleration Capabilities (Bitmask: 0x%02X):\n", cpu_feats);
    printf("  AES-NI Acceleration  : %s\n", (cpu_feats & 0x01) ? "YES" : "NO");
    printf("  ARM Crypto Ext       : %s\n", (cpu_feats & 0x02) ? "YES" : "NO");
    printf("  AVX2 SIMD Vector     : %s\n", (cpu_feats & 0x04) ? "YES" : "NO");
    printf("  ARM NEON SIMD        : %s\n\n", (cpu_feats & 0x08) ? "YES" : "NO");
}

#endif /* RIVIDE_BENCH_HARNESS_H */
