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
 * @file bench_crypto.c
 * @brief Benchmark suite for SHA-3, SHAKE, and AES-GCM symmetric cryptographic primitives.
 */

#include "rivide/crypto/aes_gcm.h"

#include "bench_harness.h"

void bench_symmetric_primitives(int iters) {
    uint8_t buffer[4096];
    uint8_t out[64];
    uint8_t ct[4096];
    uint8_t key_bytes[32];
    uint8_t iv[12];
    uint8_t tag[16];
    rivide_aes_key_t aes_key;
    int i;

    memset(buffer, 0x5a, sizeof(buffer));
    memset(key_bytes, 0x1f, sizeof(key_bytes));
    memset(iv, 0x2b, sizeof(iv));

    rivide_aes256_key_expand(&aes_key, key_bytes);

    /* Scale iterations for fast symmetric primitives. */
    int sym_iters = iters * 10;

    /* SHA3-256 (4KB payload) */
    double t0 = get_time_sec();
    for (i = 0; i < sym_iters; i++) {
        rivide_sha3_256(out, buffer, sizeof(buffer));
    }
    double t1 = get_time_sec();
    double sha3_mb = ((double)sym_iters * sizeof(buffer) / (1024.0 * 1024.0)) / (t1 - t0);

    /* SHAKE-256 (4KB payload, 64-byte squeeze) */
    for (i = 0; i < sym_iters; i++) {
        rivide_shake256(out, 64, buffer, sizeof(buffer));
    }
    double t2 = get_time_sec();
    double shake_mb = ((double)sym_iters * sizeof(buffer) / (1024.0 * 1024.0)) / (t2 - t1);

    /* AES-256-GCM (4KB payload) */
    for (i = 0; i < sym_iters; i++) {
        rivide_aes_gcm_encrypt(&aes_key, iv, NULL, 0, buffer, sizeof(buffer), ct, tag);
    }
    double t3 = get_time_sec();
    double aes_mb = ((double)sym_iters * sizeof(buffer) / (1024.0 * 1024.0)) / (t3 - t2);

    printf("  SHA3-256 (4 KB)     : %8.2f MB/sec (%6.2f us/op)\n", sha3_mb,
           ((t1 - t0) / sym_iters) * 1e6);
    printf("  SHAKE-256 (4 KB)    : %8.2f MB/sec (%6.2f us/op)\n", shake_mb,
           ((t2 - t1) / sym_iters) * 1e6);
    printf("  AES-256-GCM (4 KB)  : %8.2f MB/sec (%6.2f us/op)\n", aes_mb,
           ((t3 - t2) / sym_iters) * 1e6);
}
