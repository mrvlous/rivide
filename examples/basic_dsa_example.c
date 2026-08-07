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
 * @file basic_dsa_example.c
 * @brief Demonstration of ML-DSA-65 digital signatures using the Rivide library.
 *
 * This example generates a key pair, signs a message, and verifies the
 * signature to demonstrate the complete ML-DSA workflow.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

/**
 * @brief Print a byte buffer as hexadecimal (first N bytes).
 */
static void print_hex_prefix(const char *label, const uint8_t *buf, size_t total, size_t show) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < show && i < total; i++) {
        printf("%02x", buf[i]);
    }
    if (total > show) {
        printf("... (%zu bytes total)", total);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);
    const char *message = "This is a post-quantum signed message using Rivide.";
    size_t msglen = strlen(message);
    rivide_status_t ret;

    printf("Rivide ML-DSA-65 Digital Signature Example\n\n");

    ret = rivide_init();
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Init failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    /* Generate key pair. */
    printf("[Signer] Generating ML-DSA-65 key pair...\n");
    ret = rivide_ml_dsa_65_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "KeyGen failed: %s\n", rivide_status_str(ret));
        return 1;
    }
    printf("[Signer] Public key : %d bytes\n", RIVIDE_ML_DSA_65_PK_BYTES);
    printf("[Signer] Secret key : %d bytes\n\n", RIVIDE_ML_DSA_65_SK_BYTES);

    /* Sign the message. */
    printf("[Signer] Signing message: \"%s\"\n", message);
    ret = rivide_ml_dsa_65_sign(sig, &siglen, (const uint8_t *)message, msglen, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Sign failed: %s\n", rivide_status_str(ret));
        return 1;
    }
    printf("[Signer] Signature  : %zu bytes\n", siglen);
    print_hex_prefix("[Signer] Sig prefix ", sig, siglen, 32);
    printf("\n");

    /* Verify the signature. */
    printf("[Verifier] Verifying signature...\n");
    ret = rivide_ml_dsa_65_verify(sig, siglen, (const uint8_t *)message, msglen, pk);
    if (ret == RIVIDE_SUCCESS) {
        printf("[Verifier] Signature is VALID.\n\n");
    } else {
        printf("[Verifier] Signature is INVALID: %s\n\n", rivide_status_str(ret));
        return 1;
    }

    /* Demonstrate verification failure with tampered message. */
    printf("[Verifier] Testing with tampered message...\n");
    {
        const char *tampered = "This is a post-quantum signed message using Rivide!";
        ret = rivide_ml_dsa_65_verify(sig, siglen, (const uint8_t *)tampered, strlen(tampered), pk);
        if (ret != RIVIDE_SUCCESS) {
            printf("[Verifier] Tampered message correctly REJECTED.\n");
        } else {
            printf("[Verifier] ERROR: Tampered message was accepted!\n");
            return 1;
        }
    }

    printf("\nAll operations completed successfully.\n");
    return 0;
}
