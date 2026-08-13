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
 * @file pqc_aead_channel.c
 * @brief Real-world Hybrid PQC Secure Channel: ML-KEM-768 + AES-256-GCM AEAD.
 *
 * Demonstrates combining quantum-resistant key encapsulation (ML-KEM-768) with
 * high-speed authenticated encryption (AES-256-GCM) for end-to-end data security.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t kem_ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t shared_secret[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t alice_secret[RIVIDE_ML_KEM_SS_BYTES];

    rivide_aes_key_t aes_key;
    uint8_t iv[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    uint8_t aad[20] = "Header-Auth-Context";
    const char plaintext[] = "Highly Confidential Quantum-Safe Payload Message!";
    size_t pt_len = strlen(plaintext);
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    uint8_t tag[16];
    rivide_status_t status;

    printf("Rivide Hybrid PQC (ML-KEM-768 + AES-256-GCM) Example\n");

    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 1. Recipient (Alice) generates PQC keypair */
    printf("[Alice] Generating ML-KEM-768 Keypair...\n");
    status = rivide_ml_kem_768_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keygen failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 2. Sender (Bob) encapsulates a 256-bit symmetric key using Alice's public key */
    printf("[Bob] Encapsulating 256-bit symmetric session key...\n");
    status = rivide_ml_kem_768_encaps(kem_ct, shared_secret, pk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Encapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 3. Bob uses the PQC shared secret to encrypt the payload with AES-256-GCM */
    printf("[Bob] Encrypting payload using AES-256-GCM AEAD...\n");
    status = rivide_aes256_key_expand(&aes_key, shared_secret);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Key expansion failed: %s\n", rivide_status_str(status));
        return 1;
    }
    status = rivide_aes_gcm_encrypt(&aes_key, iv, aad, sizeof(aad), (const uint8_t *)plaintext,
                                    pt_len, ciphertext, tag);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "AEAD encrypt failed: %s\n", rivide_status_str(status));
        return 1;
    }

    printf("[Network] Transmitting PQC Ciphertext (%d bytes) & AEAD Payload (%zu bytes)...\n",
           RIVIDE_ML_KEM_768_CT_BYTES, pt_len);

    /* 4. Alice decapsulates the shared secret from the KEM ciphertext */
    printf("[Alice] Decapsulating session key from KEM ciphertext...\n");
    status = rivide_ml_kem_768_decaps(alice_secret, kem_ct, sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Decapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 5. Alice decrypts and authenticates the AEAD payload */
    printf("[Alice] Decrypting payload using decapsulated session key...\n");
    status = rivide_aes256_key_expand(&aes_key, alice_secret);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Key expansion failed: %s\n", rivide_status_str(status));
        return 1;
    }
    status =
        rivide_aes_gcm_decrypt(&aes_key, iv, aad, sizeof(aad), ciphertext, pt_len, tag, recovered);

    if (status == RIVIDE_SUCCESS) {
        recovered[pt_len] = '\0';
        printf("[SUCCESS] Payload Decrypted & Authenticated Successfully!\nMessage: \"%s\"\n",
               (const char *)recovered);
    } else {
        printf("[FAILURE] Payload decryption failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Clean secrets */
    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(shared_secret, sizeof(shared_secret));
    rivide_cleanse(alice_secret, sizeof(alice_secret));

    return 0;
}
