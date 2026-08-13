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
 * @file pqc_bench.c
 * @brief Performance benchmarking harness for Rivide PQC algorithms and primitives.
 *
 * Measures operations-per-second (ops/sec) and latency (us/op) for KeyGen, Encapsulation,
 * Decapsulation, Signing, and Verification routines.
 */

#if !defined(_WIN32) && !defined(_WIN64)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static double get_time_sec(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <time.h>
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
#endif

#include "rivide/rivide.h"

/**
 * @brief Number of iterations per benchmark run.
 */
#define BENCH_ITERATIONS 100

/**
 * @brief Execute benchmark suite for ML-KEM-768 routines.
 */
static void bench_ml_kem_768(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss1[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss2[RIVIDE_ML_KEM_SS_BYTES];
    int i;

    double t0 = get_time_sec();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        rivide_ml_kem_768_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        rivide_ml_kem_768_encaps(ct, ss1, pk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        rivide_ml_kem_768_decaps(ss2, ct, sk);
    }
    double t3 = get_time_sec();

    printf("  ML-KEM-768 KeyGen   : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t1 - t0), ((t1 - t0) / BENCH_ITERATIONS) * 1e6);
    printf("  ML-KEM-768 Encaps   : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t2 - t1), ((t2 - t1) / BENCH_ITERATIONS) * 1e6);
    printf("  ML-KEM-768 Decaps   : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t3 - t2), ((t3 - t2) / BENCH_ITERATIONS) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss1, sizeof(ss1));
    rivide_cleanse(ss2, sizeof(ss2));
}

/**
 * @brief Execute benchmark suite for ML-DSA-65 routines.
 */
static void bench_ml_dsa_65(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);
    int i;

    static const uint8_t msg[] =
        "Rivide benchmark payload for digital signature algorithm performance.";

    double t0 = get_time_sec();
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        rivide_ml_dsa_65_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        siglen = sizeof(sig);
        rivide_ml_dsa_65_sign(sig, &siglen, msg, sizeof(msg) - 1, sk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        rivide_ml_dsa_65_verify(sig, siglen, msg, sizeof(msg) - 1, pk);
    }
    double t3 = get_time_sec();

    printf("  ML-DSA-65  KeyGen   : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t1 - t0), ((t1 - t0) / BENCH_ITERATIONS) * 1e6);
    printf("  ML-DSA-65  Sign     : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t2 - t1), ((t2 - t1) / BENCH_ITERATIONS) * 1e6);
    printf("  ML-DSA-65  Verify   : %8.2f ops/sec (%6.2f us/op)\n",
           (double)BENCH_ITERATIONS / (t3 - t2), ((t3 - t2) / BENCH_ITERATIONS) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
}

int main(void) {
    uint32_t cpu_feats;

    printf("Rivide Post-Quantum Cryptography Benchmark Suite v%s\n\n", rivide_version_string());

    if (rivide_init() != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide library.\n");
        return 1;
    }

    cpu_feats = rivide_get_cpu_features();
    printf("Detected Hardware Acceleration Capabilities (Bitmask: 0x%02X):\n", cpu_feats);
    printf("  AES-NI Acceleration  : %s\n", (cpu_feats & 0x01) ? "YES" : "NO");
    printf("  ARM Crypto Ext       : %s\n", (cpu_feats & 0x02) ? "YES" : "NO");
    printf("  AVX2 SIMD Vector     : %s\n", (cpu_feats & 0x04) ? "YES" : "NO");
    printf("  ARM NEON SIMD        : %s\n\n", (cpu_feats & 0x08) ? "YES" : "NO");

    printf("Executing Benchmarks (%d iterations per operation)...\n\n", BENCH_ITERATIONS);
    bench_ml_kem_768();
    printf("\n");
    bench_ml_dsa_65();

    printf("\n[SUCCESS] Benchmark Suite Execution Complete.\n");
    return 0;
}
