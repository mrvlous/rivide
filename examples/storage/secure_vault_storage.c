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
 * @file secure_vault_storage.c
 * @brief Post-Quantum Secure File Vault & Key Storage (ML-KEM-1024 + SHA3-512).
 *
 * Demonstrates encrypting sensitive files for offline long-term storage using
 * maximum-security ML-KEM-1024 (Category 5) key encapsulation and SHA3-512 key derivation.
 */

#include <stdio.h>
#include <string.h>

#include "rivide/rivide.h"

int main(void) {
    uint8_t vault_pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t vault_sk[RIVIDE_ML_KEM_1024_SK_BYTES];
    uint8_t kem_ct[RIVIDE_ML_KEM_1024_CT_BYTES];

    uint8_t raw_shared[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t derived_key[64]; /* SHA3-512 output */

    rivide_aes_key_t aes_key;
    uint8_t iv[12] = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44};
    uint8_t vault_header[16] = "RIVIDE-VAULT-V1";

    const char sensitive_data[] = "Top-Secret Cryptographic Vault Contents:\n"
                                  "Master Passwords, Wallet Seeds, & Sovereign Credentials.";
    size_t data_len = strlen(sensitive_data);

    uint8_t encrypted_vault[128];
    uint8_t decrypted_vault[128];
    uint8_t auth_tag[16];
    uint8_t unlock_shared[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t unlock_derived[64];
    rivide_status_t status;

    printf("Post-Quantum Secure Vault Storage (ML-KEM-1024 + SHA3-512)\n");

    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 1. Generate Vault Keypair (Category 5 High-Security Level) */
    printf("[Vault Setup] Generating ML-KEM-1024 Vault Keypair...\n");
    status = rivide_ml_kem_1024_keygen(vault_pk, vault_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* 2. Encapsulate session secret and derive 512-bit key via SHA3-512 */
    printf("[Vault Lock] Encapsulating Vault Key & Deriving AES Key via SHA3-512...\n");
    status = rivide_ml_kem_1024_encaps(kem_ct, raw_shared, vault_pk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Encapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }
    rivide_sha3_512(derived_key, raw_shared, RIVIDE_ML_KEM_SS_BYTES);

    /* 3. Encrypt data payload with AES-256-GCM using first 32 bytes of derived key */
    printf("[Vault Lock] Encrypting File Payload into Vault...\n");
    status = rivide_aes256_key_expand(&aes_key, derived_key);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Key expansion failed: %s\n", rivide_status_str(status));
        return 1;
    }
    status = rivide_aes_gcm_encrypt(&aes_key, iv, vault_header, sizeof(vault_header),
                                    (const uint8_t *)sensitive_data, data_len, encrypted_vault,
                                    auth_tag);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Vault encryption failed: %s\n", rivide_status_str(status));
        return 1;
    }

    printf(
        "[Disk Storage] Vault File Written Successfully (%d bytes KEM CT + %zu bytes Payload).\n",
        RIVIDE_ML_KEM_1024_CT_BYTES, data_len);

    /* 4. Unlock Vault: Decapsulate key and decrypt payload */
    printf("[Vault Unlock] Decapsulating Secret Key from Storage Container...\n");
    status = rivide_ml_kem_1024_decaps(unlock_shared, kem_ct, vault_sk);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Decapsulation failed: %s\n", rivide_status_str(status));
        return 1;
    }
    rivide_sha3_512(unlock_derived, unlock_shared, RIVIDE_ML_KEM_SS_BYTES);

    status = rivide_aes256_key_expand(&aes_key, unlock_derived);
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Key expansion failed: %s\n", rivide_status_str(status));
        return 1;
    }
    status = rivide_aes_gcm_decrypt(&aes_key, iv, vault_header, sizeof(vault_header),
                                    encrypted_vault, data_len, auth_tag, decrypted_vault);

    if (status == RIVIDE_SUCCESS) {
        decrypted_vault[data_len] = '\0';
        printf("[SUCCESS] Secure Vault Unlocked & Decrypted!\nFile Contents:\n\"%s\"\n",
               (const char *)decrypted_vault);
    } else {
        printf("[FAILURE] Vault unlock failed: %s\n", rivide_status_str(status));
        return 1;
    }

    /* Clean sensitive keys */
    rivide_cleanse(vault_sk, sizeof(vault_sk));
    rivide_cleanse(raw_shared, sizeof(raw_shared));
    rivide_cleanse(derived_key, sizeof(derived_key));
    rivide_cleanse(unlock_shared, sizeof(unlock_shared));
    rivide_cleanse(unlock_derived, sizeof(unlock_derived));

    return 0;
}
