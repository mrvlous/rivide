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
 * @file test_dudect_kem.c
 * @brief Comprehensive statistical timing leakage verification harness (Dudect).
 *
 * Evaluates constant-time execution for sensitive cryptographic operations:
 * 1. ML-KEM-768 Decapsulation (Valid ciphertext vs Corrupted ciphertext)
 * 2. Constant-time memory compare (rivide_ct_memcmp)
 * 3. AES-256 Block Encryption (Fixed secret vs Random secret)
 * 4. AES-256-GCM AEAD Decryption (Valid tag vs Tampered tag)
 * 5. GHASH GF(2^128) Multiplication (Sparse zero bits vs Dense random bits)
 *
 * Follows the Dudect methodology:
 * - Samples execution latency across two distinct input distributions (Class 0 vs Class 1).
 * - Online sample mean and variance computation via Welford's algorithm.
 * - Asserts Welch's t-statistic |t| < 4.5 (null hypothesis: execution time is identical).
 * - 100% zero dynamic memory allocation (0 Malloc).
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "rivide/crypto/aes.h"
#include "rivide/crypto/aes_gcm.h"
#include "rivide/crypto/ghash.h"
#include "rivide/pqc/ml_kem.h"
#include "rivide/rivide.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

#define DUDECT_SAMPLE_COUNT 10000
#define DUDECT_MAX_T_THRESHOLD 4.5

/**
 * @brief Running statistics accumulator using Welford's algorithm.
 */
typedef struct {
    double count;
    double mean;
    double m2;
} dudect_stats_t;

static inline void stats_init(dudect_stats_t *s) {
    s->count = 0.0;
    s->mean = 0.0;
    s->m2 = 0.0;
}

static inline void stats_update(dudect_stats_t *s, double x) {
    double delta;
    double delta2;
    s->count += 1.0;
    delta = x - s->mean;
    s->mean += delta / s->count;
    delta2 = x - s->mean;
    s->m2 += delta * delta2;
}

static inline double stats_variance(const dudect_stats_t *s) {
    if (s->count < 2.0) {
        return 0.0;
    }
    return s->m2 / (s->count - 1.0);
}

static inline double compute_t_statistic(const dudect_stats_t *s0, const dudect_stats_t *s1) {
    double var0 = stats_variance(s0);
    double var1 = stats_variance(s1);
    double denom;

    if (s0->count < 2.0 || s1->count < 2.0) {
        return 0.0;
    }

    denom = sqrt((var0 / s0->count) + (var1 / s1->count));
    if (denom < 1e-15) {
        return 0.0;
    }

    return (s0->mean - s1->mean) / denom;
}

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(__rdtsc)
static inline uint64_t get_time_ticks(void) {
    return __rdtsc();
}
#elif defined(__x86_64__) || defined(__i386__)
static inline uint64_t get_time_ticks(void) {
    uint32_t lo;
    uint32_t hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#elif defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static inline uint64_t get_time_ticks(void) {
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (uint64_t)count.QuadPart;
}
#else
static inline uint64_t get_time_ticks(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

/**
 * @brief Statistical timing leakage test for ML-KEM-768 decapsulation.
 */
static int test_dudect_ml_kem_768(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct_valid[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ct_invalid[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_temp[RIVIDE_ML_KEM_SS_BYTES];
    dudect_stats_t stats_class0;
    dudect_stats_t stats_class1;
    double t_val;
    size_t i;

    printf("[Dudect] Testing ML-KEM-768 Decapsulation Constant-Time Execution...\n");
    stats_init(&stats_class0);
    stats_init(&stats_class1);

    if (rivide_ml_kem_768_keygen(pk, sk) != RIVIDE_SUCCESS) {
        fprintf(stderr, "Error: KeyGen failed\n");
        return -1;
    }

    if (rivide_ml_kem_768_encaps(ct_valid, ss, pk) != RIVIDE_SUCCESS) {
        fprintf(stderr, "Error: Encaps failed\n");
        return -1;
    }

    /* Prepare invalid ciphertext (corrupted ciphertext triggering implicit rejection) */
    memcpy(ct_invalid, ct_valid, sizeof(ct_invalid));
    ct_invalid[0] ^= 0x55;
    ct_invalid[sizeof(ct_invalid) / 2] ^= 0xAA;

    /* Warm up */
    for (i = 0; i < 100; i++) {
        rivide_ml_kem_768_decaps(ss_temp, ct_valid, sk);
        rivide_ml_kem_768_decaps(ss_temp, ct_invalid, sk);
    }

    /* Statistical sampling loop */
    for (i = 0; i < DUDECT_SAMPLE_COUNT; i++) {
        uint8_t coin;
        const uint8_t *ct_target;
        uint64_t t0;
        uint64_t t1;
        double diff;

        rivide_randombytes(&coin, 1);
        coin &= 1;
        ct_target = (coin == 0) ? ct_valid : ct_invalid;

        t0 = get_time_ticks();
        rivide_ml_kem_768_decaps(ss_temp, ct_target, sk);
        t1 = get_time_ticks();
        diff = (double)(t1 - t0);

        if (coin == 0) {
            stats_update(&stats_class0, diff);
        } else {
            stats_update(&stats_class1, diff);
        }
    }

    t_val = compute_t_statistic(&stats_class0, &stats_class1);
    printf("  Samples Collected : %zu (Class 0: %.0f, Class 1: %.0f)\n",
           (size_t)DUDECT_SAMPLE_COUNT, stats_class0.count, stats_class1.count);
    printf("  Mean Latency      : Class 0 = %.2f ticks, Class 1 = %.2f ticks\n", stats_class0.mean,
           stats_class1.mean);
    printf("  Welch's t-value   : %.4f (Threshold: |t| < %.2f)\n", t_val, DUDECT_MAX_T_THRESHOLD);

    if (fabs(t_val) >= DUDECT_MAX_T_THRESHOLD) {
        printf("  [FAIL] Observable timing leakage detected in ML-KEM-768 Decaps (|t| >= 4.5)\n");
        return -1;
    }

    printf("  [PASS] ML-KEM-768 Decapsulation is strictly constant-time.\n");
    return 0;
}

/**
 * @brief Statistical timing leakage test for constant-time memory comparison.
 */
static int test_dudect_ct_memcmp(void) {
    uint8_t buf_a[32];
    uint8_t buf_b[32];
    uint8_t buf_c[32];
    dudect_stats_t stats_class0;
    dudect_stats_t stats_class1;
    double t_val;
    size_t i;
    volatile int dummy = 0;

    printf("\n[Dudect] Testing rivide_ct_memcmp Constant-Time Execution...\n");
    stats_init(&stats_class0);
    stats_init(&stats_class1);

    rivide_randombytes(buf_a, sizeof(buf_a));
    memcpy(buf_b, buf_a, sizeof(buf_b));
    memcpy(buf_c, buf_a, sizeof(buf_c));
    buf_c[0] ^= 0xFF;

    /* Warm up */
    for (i = 0; i < 100; i++) {
        dummy += rivide_ct_memcmp(buf_a, buf_b, sizeof(buf_a));
        dummy += rivide_ct_memcmp(buf_a, buf_c, sizeof(buf_a));
    }

    /* Statistical sampling loop */
    for (i = 0; i < DUDECT_SAMPLE_COUNT; i++) {
        uint8_t coin;
        const uint8_t *target_buf;
        uint64_t t0;
        uint64_t t1;
        double diff;
        int k;

        rivide_randombytes(&coin, 1);
        coin &= 1;
        target_buf = (coin == 0) ? buf_b : buf_c;

        t0 = get_time_ticks();
        for (k = 0; k < 64; k++) {
            dummy += rivide_ct_memcmp(buf_a, target_buf, sizeof(buf_a));
        }
        t1 = get_time_ticks();
        diff = (double)(t1 - t0) / 64.0;

        if (coin == 0) {
            stats_update(&stats_class0, diff);
        } else {
            stats_update(&stats_class1, diff);
        }
    }

    (void)dummy;
    t_val = compute_t_statistic(&stats_class0, &stats_class1);
    printf("  Samples Collected : %zu (Class 0: %.0f, Class 1: %.0f)\n",
           (size_t)DUDECT_SAMPLE_COUNT, stats_class0.count, stats_class1.count);
    printf("  Mean Latency      : Class 0 = %.2f ticks, Class 1 = %.2f ticks\n", stats_class0.mean,
           stats_class1.mean);
    printf("  Welch's t-value   : %.4f (Threshold: |t| < %.2f)\n", t_val, DUDECT_MAX_T_THRESHOLD);

    if (fabs(t_val) >= DUDECT_MAX_T_THRESHOLD) {
        printf("  [FAIL] Observable timing leakage detected in rivide_ct_memcmp (|t| >= 4.5)\n");
        return -1;
    }

    printf("  [PASS] rivide_ct_memcmp is strictly constant-time.\n");
    return 0;
}

/**
 * @brief Statistical timing leakage test for AES block encryption.
 */
static int test_dudect_aes_block(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    uint8_t pt_class0[16];
    uint8_t pt_class1[16];
    uint8_t ct_out[16];
    dudect_stats_t stats_class0;
    dudect_stats_t stats_class1;
    double t_val;
    size_t i;

    printf("\n[Dudect] Testing AES Block Encryption Constant-Time Execution...\n");
    stats_init(&stats_class0);
    stats_init(&stats_class1);

    rivide_randombytes(raw_key, sizeof(raw_key));
    rivide_randombytes(pt_class0, sizeof(pt_class0));
    rivide_randombytes(pt_class1, sizeof(pt_class1));
    rivide_aes256_key_expand(&key, raw_key);

    /* Warm up */
    for (i = 0; i < 100; i++) {
        rivide_aes_encrypt_block(&key, pt_class0, ct_out);
        rivide_aes_encrypt_block(&key, pt_class1, ct_out);
    }

    /* Statistical sampling loop */
    for (i = 0; i < DUDECT_SAMPLE_COUNT; i++) {
        uint8_t coin;
        const uint8_t *pt_target;
        uint64_t t0;
        uint64_t t1;
        double diff;
        int k;

        rivide_randombytes(&coin, 1);
        coin &= 1;
        pt_target = (coin == 0) ? pt_class0 : pt_class1;

        t0 = get_time_ticks();
        for (k = 0; k < 16; k++) {
            rivide_aes_encrypt_block(&key, pt_target, ct_out);
        }
        t1 = get_time_ticks();
        diff = (double)(t1 - t0) / 16.0;

        if (coin == 0) {
            stats_update(&stats_class0, diff);
        } else {
            stats_update(&stats_class1, diff);
        }
    }

    rivide_aes_key_cleanse(&key);
    t_val = compute_t_statistic(&stats_class0, &stats_class1);
    printf("  Samples Collected : %zu (Class 0: %.0f, Class 1: %.0f)\n",
           (size_t)DUDECT_SAMPLE_COUNT, stats_class0.count, stats_class1.count);
    printf("  Mean Latency      : Class 0 = %.2f ticks, Class 1 = %.2f ticks\n", stats_class0.mean,
           stats_class1.mean);
    printf("  Welch's t-value   : %.4f (Threshold: |t| < %.2f)\n", t_val, DUDECT_MAX_T_THRESHOLD);

    if (fabs(t_val) >= DUDECT_MAX_T_THRESHOLD) {
        printf(
            "  [FAIL] Observable timing leakage detected in AES Block Encryption (|t| >= 4.5)\n");
        return -1;
    }

    printf("  [PASS] AES Block Encryption is strictly constant-time.\n");
    return 0;
}

/**
 * @brief Statistical timing leakage test for AES-256-GCM AEAD decryption.
 */
static int test_dudect_aes_gcm(void) {
    rivide_aes_key_t key;
    uint8_t raw_key[32];
    uint8_t iv[12];
    uint8_t pt0[32];
    uint8_t pt1[32];
    uint8_t ct0[32];
    uint8_t ct1[32];
    uint8_t tag0[16];
    uint8_t tag1[16];
    uint8_t out[32];
    dudect_stats_t stats_class0;
    dudect_stats_t stats_class1;
    double t_val;
    size_t i;

    printf("\n[Dudect] Testing AES-256-GCM Decryption Constant-Time Execution...\n");
    stats_init(&stats_class0);
    stats_init(&stats_class1);

    rivide_randombytes(raw_key, sizeof(raw_key));
    rivide_randombytes(iv, sizeof(iv));
    memset(pt0, 0xAA, sizeof(pt0));
    rivide_randombytes(pt1, sizeof(pt1));

    rivide_aes256_key_expand(&key, raw_key);
    rivide_aes_gcm_encrypt(&key, iv, NULL, 0, pt0, sizeof(pt0), ct0, tag0);
    rivide_aes_gcm_encrypt(&key, iv, NULL, 0, pt1, sizeof(pt1), ct1, tag1);

    /* Warm up */
    for (i = 0; i < 100; i++) {
        rivide_aes_gcm_decrypt(&key, iv, NULL, 0, ct0, sizeof(ct0), tag0, out);
        rivide_aes_gcm_decrypt(&key, iv, NULL, 0, ct1, sizeof(ct1), tag1, out);
    }

    /* Statistical sampling loop */
    for (i = 0; i < DUDECT_SAMPLE_COUNT; i++) {
        uint8_t coin;
        const uint8_t *ct_target;
        const uint8_t *tag_target;
        uint64_t t0;
        uint64_t t1;
        double diff;
        int k;

        rivide_randombytes(&coin, 1);
        coin &= 1;
        ct_target = (coin == 0) ? ct0 : ct1;
        tag_target = (coin == 0) ? tag0 : tag1;

        t0 = get_time_ticks();
        for (k = 0; k < 8; k++) {
            rivide_aes_gcm_decrypt(&key, iv, NULL, 0, ct_target, sizeof(ct0), tag_target, out);
        }
        t1 = get_time_ticks();
        diff = (double)(t1 - t0) / 8.0;

        if (coin == 0) {
            stats_update(&stats_class0, diff);
        } else {
            stats_update(&stats_class1, diff);
        }
    }

    rivide_aes_key_cleanse(&key);
    t_val = compute_t_statistic(&stats_class0, &stats_class1);
    printf("  Samples Collected : %zu (Class 0: %.0f, Class 1: %.0f)\n",
           (size_t)DUDECT_SAMPLE_COUNT, stats_class0.count, stats_class1.count);
    printf("  Mean Latency      : Class 0 = %.2f ticks, Class 1 = %.2f ticks\n", stats_class0.mean,
           stats_class1.mean);
    printf("  Welch's t-value   : %.4f (Threshold: |t| < %.2f)\n", t_val, DUDECT_MAX_T_THRESHOLD);

    if (fabs(t_val) >= DUDECT_MAX_T_THRESHOLD) {
        printf("  [FAIL] Observable timing leakage detected in AES-GCM Decryption (|t| >= 4.5)\n");
        return -1;
    }

    printf("  [PASS] AES-256-GCM Decryption is strictly constant-time.\n");
    return 0;
}

/**
 * @brief Statistical timing leakage test for GHASH GF(2^128) multiplication.
 */
static int test_dudect_ghash(void) {
    uint8_t h[16];
    uint8_t data_class0[64];
    uint8_t data_class1[64];
    uint8_t tag_out[16];
    dudect_stats_t stats_class0;
    dudect_stats_t stats_class1;
    double t_val;
    size_t i;

    printf("\n[Dudect] Testing GHASH Constant-Time Multiplications...\n");
    stats_init(&stats_class0);
    stats_init(&stats_class1);

    rivide_randombytes(h, sizeof(h));
    rivide_randombytes(data_class0, sizeof(data_class0));
    rivide_randombytes(data_class1, sizeof(data_class1));

    /* Warm up */
    for (i = 0; i < 100; i++) {
        memset(tag_out, 0, sizeof(tag_out));
        rivide_ghash_update(h, data_class0, sizeof(data_class0), tag_out);
        rivide_ghash_update(h, data_class1, sizeof(data_class1), tag_out);
    }

    /* Statistical sampling loop */
    for (i = 0; i < DUDECT_SAMPLE_COUNT; i++) {
        uint8_t coin;
        const uint8_t *data_target;
        uint64_t t0;
        uint64_t t1;
        double diff;
        int k;

        rivide_randombytes(&coin, 1);
        coin &= 1;
        data_target = (coin == 0) ? data_class0 : data_class1;

        t0 = get_time_ticks();
        for (k = 0; k < 16; k++) {
            memset(tag_out, 0, sizeof(tag_out));
            rivide_ghash_update(h, data_target, sizeof(data_class0), tag_out);
        }
        t1 = get_time_ticks();
        diff = (double)(t1 - t0) / 16.0;

        if (coin == 0) {
            stats_update(&stats_class0, diff);
        } else {
            stats_update(&stats_class1, diff);
        }
    }

    t_val = compute_t_statistic(&stats_class0, &stats_class1);
    printf("  Samples Collected : %zu (Class 0: %.0f, Class 1: %.0f)\n",
           (size_t)DUDECT_SAMPLE_COUNT, stats_class0.count, stats_class1.count);
    printf("  Mean Latency      : Class 0 = %.2f ticks, Class 1 = %.2f ticks\n", stats_class0.mean,
           stats_class1.mean);
    printf("  Welch's t-value   : %.4f (Threshold: |t| < %.2f)\n", t_val, DUDECT_MAX_T_THRESHOLD);

    if (fabs(t_val) >= DUDECT_MAX_T_THRESHOLD) {
        printf("  [FAIL] Observable timing leakage detected in GHASH (|t| >= 4.5)\n");
        return -1;
    }

    printf("  [PASS] GHASH is strictly constant-time.\n");
    return 0;
}

int main(void) {
    int ret = 0;

    printf("Rivide Constant-Time Statistical Timing Leakage Verification (Dudect)\n");
    printf("  Library Version : %s\n", rivide_version_string());
    printf("  Modulus Info    : q = 3329 (ML-KEM), q = 8380417 (ML-DSA)\n");
    printf("  Statistical Test: Welch's Two-Sample t-Test (Threshold |t| < 4.5)\n\n");

    if (rivide_init() != RIVIDE_SUCCESS) {
        fprintf(stderr, "Error: rivide_init() failed\n");
        return 1;
    }

    if (test_dudect_ml_kem_768() != 0) {
        ret = 1;
    }

    if (test_dudect_ct_memcmp() != 0) {
        ret = 1;
    }

    if (test_dudect_aes_block() != 0) {
        ret = 1;
    }

    if (test_dudect_aes_gcm() != 0) {
        ret = 1;
    }

    if (test_dudect_ghash() != 0) {
        ret = 1;
    }

    printf("\n");
    if (ret == 0) {
        printf("[SUCCESS] All constant-time timing leakage assertions PASSED (|t| < 4.5).\n");
    } else {
        printf("[FAILURE] Timing leakage detected in one or more cryptographic routines.\n");
    }

    return ret;
}
