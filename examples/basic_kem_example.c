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
 * @file basic_kem_example.c
 * @brief Demonstration of ML-KEM-768 key exchange using the Rivide library.
 *
 * This example performs a complete key encapsulation/decapsulation cycle
 * and prints the resulting shared secrets to verify they match.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

/**
 * @brief Print a byte buffer as hexadecimal.
 */
static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_enc[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_dec[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t ret;

    printf("Rivide ML-KEM-768 Key Exchange Example\n\n");

    ret = rivide_init();
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Init failed: %s\n", rivide_status_str(ret));
        return 1;
    }

    /* Alice generates a key pair. */
    printf("[Alice] Generating ML-KEM-768 key pair...\n");
    ret = rivide_ml_kem_768_keygen(pk, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "KeyGen failed: %s\n", rivide_status_str(ret));
        return 1;
    }
    printf("[Alice] Public key : %d bytes\n", RIVIDE_ML_KEM_768_PK_BYTES);
    printf("[Alice] Secret key : %d bytes\n\n", RIVIDE_ML_KEM_768_SK_BYTES);

    /* Bob encapsulates a shared secret using Alice's public key. */
    printf("[Bob]   Encapsulating shared secret...\n");
    ret = rivide_ml_kem_768_encaps(ct, ss_enc, pk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Encaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }
    printf("[Bob]   Ciphertext : %d bytes\n", RIVIDE_ML_KEM_768_CT_BYTES);
    print_hex("[Bob]   Shared key ", ss_enc, RIVIDE_ML_KEM_SS_BYTES);
    printf("\n");

    /* Alice decapsulates the shared secret from Bob's ciphertext. */
    printf("[Alice] Decapsulating shared secret...\n");
    ret = rivide_ml_kem_768_decaps(ss_dec, ct, sk);
    if (ret != RIVIDE_SUCCESS) {
        fprintf(stderr, "Decaps failed: %s\n", rivide_status_str(ret));
        return 1;
    }
    print_hex("[Alice] Shared key ", ss_dec, RIVIDE_ML_KEM_SS_BYTES);
    printf("\n");

    /* Verify shared secrets match. */
    if (memcmp(ss_enc, ss_dec, RIVIDE_ML_KEM_SS_BYTES) == 0) {
        printf("SUCCESS: Shared secrets match!\n");
    } else {
        printf("FAILURE: Shared secrets do not match.\n");
        return 1;
    }

    return 0;
}
