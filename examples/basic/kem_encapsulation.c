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
 * @file kem_encapsulation.c
 * @brief Basic ML-KEM-768 key encapsulation and decapsulation example.
 *
 * Demonstrates how Alice generates a keypair, sends her public key to Bob,
 * Bob encapsulates a secret shared key, and Alice decapsulates it.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t alice_shared_key[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t bob_shared_key[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t status;
    int i;

    printf("Rivide ML-KEM-768 (FIPS 203) Key Encapsulation Example\n");

    /* Initialize Rivide library */
    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Step 1: Alice generates ML-KEM-768 keypair */
    printf("[Alice] Generating ML-KEM-768 keypair...\n");
    status = rivide_ml_kem_768_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keygen failed: %s\n", rivide_status_str(status));
        return 1;
    }
    printf("[Alice] Public key generated (%d bytes)\n", RIVIDE_ML_KEM_768_PK_BYTES);

    /* Step 2: Bob encapsulates a 32-byte shared secret using Alice's public key */
    printf("[Bob] Encapsulating shared key using Alice's public key...\n");
    status = rivide_ml_kem_768_encaps(ct, bob_shared_key, pk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Encapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }
    printf("[Bob] Ciphertext created (%d bytes)\n", RIVIDE_ML_KEM_768_CT_BYTES);

    /* Step 3: Alice decapsulates the shared secret using her secret key */
    printf("[Alice] Decapsulating ciphertext using her secret key...\n");
    status = rivide_ml_kem_768_decaps(alice_shared_key, ct, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Decapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Step 4: Verify that Alice and Bob established the exact same secret key */
    if (memcmp(alice_shared_key, bob_shared_key, RIVIDE_ML_KEM_SS_BYTES) == 0) {
        printf("[SUCCESS] Shared keys match perfectly!\nKey: ");
        for (i = 0; i < 16; i++) {
            printf("%02x", alice_shared_key[i]);
        }
        printf("...\n");
    } else {
        printf("[FAILURE] Key mismatch!\n");
        return 1;
    }

    /* Clean up sensitive secret keys */
    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(alice_shared_key, sizeof(alice_shared_key));
    rivide_cleanse(bob_shared_key, sizeof(bob_shared_key));

    return 0;
}
