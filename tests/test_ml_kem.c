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
 * @file test_ml_kem.c
 * @brief ML-KEM round-trip and correctness tests.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

/**
 * @brief ML-KEM-768 full round-trip: keygen -> encaps -> decaps.
 *
 * Verifies that the shared secrets produced by encapsulation and
 * decapsulation are identical.
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_kem_768_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_enc[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_dec[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t ret;

    ret = rivide_ml_kem_768_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    keygen failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_kem_768_encaps(ct, ss_enc, pk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    encaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_kem_768_decaps(ss_dec, ct, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    decaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    if (memcmp(ss_enc, ss_dec, RIVIDE_ML_KEM_SS_BYTES) != 0) {
        int match = 0;
        for (int i = 0; i < RIVIDE_ML_KEM_SS_BYTES; i++) {
            if (ss_enc[i] == ss_dec[i])
                match++;
        }
        fprintf(stderr, "    shared secrets do not match (matching bytes: %d / %d)\n", match,
                RIVIDE_ML_KEM_SS_BYTES);
        return 1;
    }

    return 0;
}

/**
 * @brief ML-KEM-768 invalid ciphertext test.
 *
 * Verifies that modifying the ciphertext causes decapsulation to produce
 * a different shared secret (implicit rejection behavior).
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_kem_768_invalid_ct(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_enc[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_dec[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t ret;

    ret = rivide_ml_kem_768_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS)
        return 1;

    ret = rivide_ml_kem_768_encaps(ct, ss_enc, pk);
    if (ret != RIVIDE_SUCCESS)
        return 1;

    /* Tamper with the ciphertext. */
    ct[0] ^= 0xFF;
    ct[100] ^= 0xAA;

    ret = rivide_ml_kem_768_decaps(ss_dec, ct, sk);
    if (ret != RIVIDE_SUCCESS)
        return 1;

    /* Shared secrets MUST differ due to implicit rejection. */
    if (memcmp(ss_enc, ss_dec, RIVIDE_ML_KEM_SS_BYTES) == 0) {
        fprintf(stderr, "    implicit rejection failed: "
                        "shared secrets match after tampering\n");
        return 1;
    }

    return 0;
}

/**
 * @brief ML-KEM-1024 full round-trip test.
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_kem_1024_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_1024_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_1024_CT_BYTES];
    uint8_t ss_enc[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_dec[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t ret;

    ret = rivide_ml_kem_1024_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    keygen failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_kem_1024_encaps(ct, ss_enc, pk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    encaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_kem_1024_decaps(ss_dec, ct, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    decaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    if (memcmp(ss_enc, ss_dec, RIVIDE_ML_KEM_SS_BYTES) != 0) {
        fprintf(stderr, "    shared secrets do not match\n");
        return 1;
    }

    return 0;
}
