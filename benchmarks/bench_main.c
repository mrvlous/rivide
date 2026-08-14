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
 * @file bench_main.c
 * @brief Main driver for the dedicated Rivide benchmark subsystem.
 */

#include "bench_harness.h"

extern void bench_ml_kem_768(int iters);
extern void bench_ml_kem_1024(int iters);
extern void bench_ml_dsa_65(int iters);
extern void bench_ml_dsa_87(int iters);
extern void bench_symmetric_primitives(int iters);

int main(int argc, char **argv) {
    int iters = get_bench_iterations(100);

    if (argc > 1) {
        int custom = atoi(argv[1]);
        if (custom > 0) {
            iters = custom;
        }
    }

    if (rivide_init() != RIVIDE_SUCCESS) {
        fprintf(stderr, "FATAL: Failed to initialize Rivide cryptographic library.\n");
        return 1;
    }

    print_bench_header(iters);

    printf("NIST FIPS 203 ML-KEM Benchmarks:\n");
    bench_ml_kem_768(iters);
    printf("\n");
    bench_ml_kem_1024(iters);

    printf("\nNIST FIPS 204 ML-DSA Benchmarks:\n");
    bench_ml_dsa_65(iters);
    printf("\n");
    bench_ml_dsa_87(iters);

    printf("\nSymmetric Cryptographic Primitives Benchmarks:\n");
    bench_symmetric_primitives(iters);

    printf("\n[SUCCESS] Dedicated Benchmark Suite Execution Complete.\n");
    return 0;
}
