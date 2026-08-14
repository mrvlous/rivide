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
 * @file bench_dsa.c
 * @brief Benchmark suite for NIST FIPS 204 ML-DSA-65 and ML-DSA-87 routines.
 */

#include "bench_harness.h"

void bench_ml_dsa_65(int iters) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);
    int i;

    static const uint8_t msg[] =
        "Rivide benchmark payload for digital signature algorithm performance.";
    size_t msglen = sizeof(msg) - 1;

    double t0 = get_time_sec();
    for (i = 0; i < iters; i++) {
        rivide_ml_dsa_65_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < iters; i++) {
        siglen = sizeof(sig);
        rivide_ml_dsa_65_sign(sig, &siglen, msg, msglen, sk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_dsa_65_verify(sig, siglen, msg, msglen, pk);
    }
    double t3 = get_time_sec();

    printf("  ML-DSA-65  KeyGen   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t1 - t0),
           ((t1 - t0) / iters) * 1e6);
    printf("  ML-DSA-65  Sign     : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t2 - t1),
           ((t2 - t1) / iters) * 1e6);
    printf("  ML-DSA-65  Verify   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t3 - t2),
           ((t3 - t2) / iters) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
}

void bench_ml_dsa_87(int iters) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = sizeof(sig);
    int i;

    static const uint8_t msg[] =
        "Rivide benchmark payload for digital signature algorithm performance.";
    size_t msglen = sizeof(msg) - 1;

    double t0 = get_time_sec();
    for (i = 0; i < iters; i++) {
        rivide_ml_dsa_87_keygen(pk, sk);
    }
    double t1 = get_time_sec();

    for (i = 0; i < iters; i++) {
        siglen = sizeof(sig);
        rivide_ml_dsa_87_sign(sig, &siglen, msg, msglen, sk);
    }
    double t2 = get_time_sec();

    for (i = 0; i < iters; i++) {
        rivide_ml_dsa_87_verify(sig, siglen, msg, msglen, pk);
    }
    double t3 = get_time_sec();

    printf("  ML-DSA-87  KeyGen   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t1 - t0),
           ((t1 - t0) / iters) * 1e6);
    printf("  ML-DSA-87  Sign     : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t2 - t1),
           ((t2 - t1) / iters) * 1e6);
    printf("  ML-DSA-87  Verify   : %8.2f ops/sec (%6.2f us/op)\n", (double)iters / (t3 - t2),
           ((t3 - t2) / iters) * 1e6);

    rivide_cleanse(sk, sizeof(sk));
}
