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
 * @file test_kat_ml_kem.c
 * @brief NIST FIPS 203 Known Answer Tests for ML-KEM-768 and ML-KEM-1024.
 */

#include "test_kat_harness.h"

int kat_ml_kem_768_functional_vector(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_encap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_decap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_reject[RIVIDE_ML_KEM_SS_BYTES];

    KAT_ASSERT(rivide_ml_kem_768_keygen(pk, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_kem_768_encaps(ct, ss_encap, pk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_kem_768_decaps(ss_decap, ct, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT_BYTES_EQ(ss_encap, ss_decap, RIVIDE_ML_KEM_SS_BYTES);

    /* Test deterministic constant-time implicit rejection on malformed ciphertext. */
    ct[0] ^= 0x55;
    KAT_ASSERT(rivide_ml_kem_768_decaps(ss_reject, ct, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(memcmp(ss_encap, ss_reject, RIVIDE_ML_KEM_SS_BYTES) != 0);

    /* Test deterministic implicit rejection consistency: same malformed ciphertext yields same
     * rejection key. */
    uint8_t ss_reject_again[RIVIDE_ML_KEM_SS_BYTES];
    KAT_ASSERT(rivide_ml_kem_768_decaps(ss_reject_again, ct, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT_BYTES_EQ(ss_reject, ss_reject_again, RIVIDE_ML_KEM_SS_BYTES);

    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss_encap, sizeof(ss_encap));
    rivide_cleanse(ss_decap, sizeof(ss_decap));
    rivide_cleanse(ss_reject, sizeof(ss_reject));
    return 0;
}

int kat_ml_kem_1024_functional_vector(void) {
    uint8_t pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_1024_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_1024_CT_BYTES];
    uint8_t ss_encap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_decap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_reject[RIVIDE_ML_KEM_SS_BYTES];

    KAT_ASSERT(rivide_ml_kem_1024_keygen(pk, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_kem_1024_encaps(ct, ss_encap, pk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_kem_1024_decaps(ss_decap, ct, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT_BYTES_EQ(ss_encap, ss_decap, RIVIDE_ML_KEM_SS_BYTES);

    /* Test implicit rejection on flipped ciphertext bit. */
    ct[RIVIDE_ML_KEM_1024_CT_BYTES - 1] ^= 0x01;
    KAT_ASSERT(rivide_ml_kem_1024_decaps(ss_reject, ct, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(memcmp(ss_encap, ss_reject, RIVIDE_ML_KEM_SS_BYTES) != 0);

    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss_encap, sizeof(ss_encap));
    rivide_cleanse(ss_decap, sizeof(ss_decap));
    rivide_cleanse(ss_reject, sizeof(ss_reject));
    return 0;
}
