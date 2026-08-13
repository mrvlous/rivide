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
 * @file detached_pdf_signer.c
 * @brief ML-DSA-87 detached document signature example.
 *
 * Demonstrates generating detached signatures for document integrity verification under NIST FIPS
 * 204.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t signature[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = 0;

    const uint8_t document[] = "CONFIDENTIAL CONTRACT AGREEMENT 2026\n"
                               "Party A agrees to transfer Post-Quantum assets to Party B.";
    size_t doc_len = strlen((const char *)document);

    rivide_status_t status;

    printf("Rivide ML-DSA-87 Detached Document Signature Example\n");

    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 1. Generate ML-DSA-87 high-security keypair */
    printf("[Signer] Generating ML-DSA-87 keypair (Security Category 5)...\n");
    status = rivide_ml_dsa_87_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 2. Sign document */
    printf("[Signer] Signing document...\n");
    status = rivide_ml_dsa_87_sign(signature, &siglen, document, doc_len, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Signing failed: %s\n", rivide_status_str(status));
        return 1;
    }
    printf("[Signer] Detached signature generated (%zu bytes)\n", siglen);

    /* 3. Verify signature */
    printf("[Auditor] Verifying detached signature...\n");
    status = rivide_ml_dsa_87_verify(signature, siglen, document, doc_len, pk);

    if (status == RIVIDE_SUCCESS) {
        printf("[SUCCESS] Document Signature is AUTHENTIC and UNTAMPERED!\n");
    } else {
        printf("[FAILURE] Verification failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Clean secrets */
    rivide_cleanse(sk, sizeof(sk));

    return 0;
}
