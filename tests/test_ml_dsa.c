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
 * @file test_ml_dsa.c
 * @brief ML-DSA round-trip and correctness tests.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

/**
 * @brief ML-DSA-65 full round-trip: keygen -> sign -> verify.
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_dsa_65_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);
    const uint8_t msg[] = "Rivide post-quantum signature test message.";
    size_t msglen = sizeof(msg) - 1;
    rivide_status_t ret;

    ret = rivide_ml_dsa_65_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    keygen failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_dsa_65_sign(sig, &siglen, msg, msglen, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    sign failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_dsa_65_verify(sig, siglen, msg, msglen, pk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    verify failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    return 0;
}

/**
 * @brief ML-DSA-65 tampered message test.
 *
 * Verifies that modifying the message causes verification to fail.
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_dsa_65_tampered_msg(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);
    uint8_t msg[] = "Original message for DSA testing.";
    size_t msglen = sizeof(msg) - 1;
    rivide_status_t ret;

    ret = rivide_ml_dsa_65_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS)
        return 1;

    ret = rivide_ml_dsa_65_sign(sig, &siglen, msg, msglen, sk);
    if (ret != RIVIDE_SUCCESS)
        return 1;

    /* Tamper with the message. */
    msg[0] ^= 0x01;

    ret = rivide_ml_dsa_65_verify(sig, siglen, msg, msglen, pk);
    if (ret == RIVIDE_SUCCESS) {
        fprintf(stderr, "    verification should have failed on tampered msg\n");
        return 1;
    }

    return 0;
}

/**
 * @brief ML-DSA-87 full round-trip test.
 *
 * @return 0 on success, 1 on failure.
 */
int test_ml_dsa_87_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = sizeof(sig);
    const uint8_t msg[] = "ML-DSA-87 round-trip verification test.";
    size_t msglen = sizeof(msg) - 1;
    rivide_status_t ret;

    ret = rivide_ml_dsa_87_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    keygen failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_dsa_87_sign(sig, &siglen, msg, msglen, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    sign failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    ret = rivide_ml_dsa_87_verify(sig, siglen, msg, msglen, pk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "    verify failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    return 0;
}
