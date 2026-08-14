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
 * @file bench_kem.c
 * @brief Benchmark suite for NIST FIPS 203 ML-KEM-768 and ML-KEM-1024 routines.
 */

#include "bench_harness.h"

void bench_ml_kem_768(int iters) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss1[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss2[RIVIDE_ML_KEM_SS_BYTES];
    int i;

    double t0 = get_time_sec();
    for (i = 0; i < iters; i++) {
        rivide_ml_kem_768_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_kem_768_encaps(ct, ss1, pk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_kem_768_decaps(ss2, ct, sk);
    }
    double t3 = get_time_sec();

    printf("  ML-KEM-768 KeyGen   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t1 - t0),
           ((t1 - t0) / iters) * 1e6);
    printf("  ML-KEM-768 Encaps   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t2 - t1),
           ((t2 - t1) / iters) * 1e6);
    printf("  ML-KEM-768 Decaps   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t3 - t2),
           ((t3 - t2) / iters) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss1, sizeof(ss1));
    rivide_cleanse(ss2, sizeof(ss2));
}

void bench_ml_kem_1024(int iters) {
    uint8_t pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_1024_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_1024_CT_BYTES];
    uint8_t ss1[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss2[RIVIDE_ML_KEM_SS_BYTES];
    int i;

    double t0 = get_time_sec();
    for (i = 0; i < iters; i++) {
        rivide_ml_kem_1024_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_kem_1024_encaps(ct, ss1, pk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_kem_1024_decaps(ss2, ct, sk);
    }
    double t3 = get_time_sec();

    printf("  ML-KEM-1024 KeyGen  : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t1 - t0),
           ((t1 - t0) / iters) * 1e6);
    printf("  ML-KEM-1024 Encaps  : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t2 - t1),
           ((t2 - t1) / iters) * 1e6);
    printf("  ML-KEM-1024 Decaps  : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t3 - t2),
           ((t3 - t2) / iters) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss1, sizeof(ss1));
    rivide_cleanse(ss2, sizeof(ss2));
}
