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
 * @file dsa_digital_signature.c
 * @brief Basic ML-DSA-65 digital signature signing and verification example.
 *
 * Demonstrates how to sign a message using ML-DSA-65 and verify its authenticity
 * and integrity using the corresponding public key.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = 0;
    const uint8_t message[] = "Post-Quantum Signed Message Content";
    size_t message_len = sizeof(message) - 1;
    rivide_status_t status;

    printf("Rivide ML-DSA-65 (FIPS 204) Digital Signature Example\n");

    /* Initialize library */
    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Initialization failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Step 1: Generate ML-DSA-65 keypair */
    printf("[Signer] Generating ML-DSA-65 keypair...\n");
    status = rivide_ml_dsa_65_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keygen failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Step 2: Sign message */
    printf("[Signer] Signing message: \"%s\"\n", (const char *)message);
    status = rivide_ml_dsa_65_sign(sig, &siglen, message, message_len, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Signing failed: %s\n", rivide_status_str(status));
        return 1;
    }
    printf("[Signer] Signature produced (%zu bytes)\n", siglen);

    /* Step 3: Verifier checks signature */
    printf("[Verifier] Verifying signature against public key...\n");
    status = rivide_ml_dsa_65_verify(sig, siglen, message, message_len, pk);
    if (status == RIVIDE_SUCCESS) {
        printf("[SUCCESS] Signature is VALID!\n");
    } else {
        printf("[FAILURE] Signature verification FAILED (%s)\n", rivide_status_str(status));
        return 1;
    }

    /* Clean secret key */
    rivide_cleanse(sk, sizeof(sk));

    return 0;
}
