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
 * @file tls_handshake_pqc.c
 * @brief Simulated Post-Quantum TLS 1.3 Handshake Protocol.
 *
 * Demonstrates combining ML-DSA-65 server authentication with ML-KEM-768 key
 * exchange to establish a quantum-safe encrypted TLS session key.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    /* Server identity keys (ML-DSA-65) */
    uint8_t server_cert_pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t server_cert_sk[RIVIDE_ML_DSA_65_SK_BYTES];

    /* Server ephemeral key exchange (ML-KEM-768) */
    uint8_t server_kem_pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t server_kem_sk[RIVIDE_ML_KEM_768_SK_BYTES];

    /* Client ephemeral key exchange output */
    uint8_t kem_ciphertext[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t client_master_secret[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t server_master_secret[RIVIDE_ML_KEM_SS_BYTES];

    /* Handshake signature authentication */
    uint8_t handshake_sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t handshake_sig_len = 0;

    rivide_status_t status;

    printf("Simulated Post-Quantum TLS 1.3 Handshake Protocol\n");

    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 1. Server Setup: Provision identity certificate and ephemeral KEM key */
    printf("[Server] Provisioning ML-DSA-65 Identity Certificate...\n");
    status = rivide_ml_dsa_65_keygen(server_cert_pk, server_cert_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    printf("[Server] Generating Ephemeral ML-KEM-768 Key Exchange Parameters...\n");
    status = rivide_ml_kem_768_keygen(server_kem_pk, server_kem_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 2. Client Hello -> Server Hello: Client encapsulates session key */
    printf("[Client] Receiving Server Public Key & Encapsulating Master Key...\n");
    status = rivide_ml_kem_768_encaps(kem_ciphertext, client_master_secret, server_kem_pk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Encapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 3. Server authenticates handshake by signing KEM ciphertext with certificate */
    printf("[Server] Signing Handshake Parameters with ML-DSA-65 Certificate...\n");
    status = rivide_ml_dsa_65_sign(handshake_sig, &handshake_sig_len, kem_ciphertext,
                                   sizeof(kem_ciphertext), server_cert_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Signing failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 4. Client verifies Server's certificate signature */
    printf("[Client] Verifying Server Handshake Signature...\n");
    status = rivide_ml_dsa_65_verify(handshake_sig, handshake_sig_len, kem_ciphertext,
                                     sizeof(kem_ciphertext), server_cert_pk);

    if (status == RIVIDE_SUCCESS) {
        printf("[Client] Server Certificate Authenticated Successfully!\n");
    } else {
        printf("[Client] Server Authentication Failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 5. Server decapsulates master secret */
    printf("[Server] Decapsulating Master Secret...\n");
    status = rivide_ml_kem_768_decaps(server_master_secret, kem_ciphertext, server_kem_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Decapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 6. Handshake Complete: Verify shared master secret match */
    if (memcmp(client_master_secret, server_master_secret, RIVIDE_ML_KEM_SS_BYTES) == 0) {
        printf("[SUCCESS] Post-Quantum TLS 1.3 Handshake Complete! Quantum-Safe Tunnel "
               "Established.\n");
    } else {
        printf("[FAILURE] Handshake Master Key Mismatch!\n");
        return 1;
    }

    /* Clean sensitive materials */
    rivide_cleanse(server_cert_sk, sizeof(server_cert_sk));
    rivide_cleanse(server_kem_sk, sizeof(server_kem_sk));
    rivide_cleanse(client_master_secret, sizeof(client_master_secret));
    rivide_cleanse(server_master_secret, sizeof(server_master_secret));

    return 0;
}
