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
 * @file test_ml_kem.c
 * @brief Unit tests for NIST FIPS 203 ML-KEM-768 and ML-KEM-1024.
 */

#include "rivide/pqc/ml_kem.h"

#include "test_harness.h"

int test_ml_kem_768_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_encap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_decap[RIVIDE_ML_KEM_SS_BYTES];

    ASSERT_OK(rivide_ml_kem_768_keygen(pk, sk));
    ASSERT_OK(rivide_ml_kem_768_encaps(ct, ss_encap, pk));
    ASSERT_OK(rivide_ml_kem_768_decaps(ss_decap, ct, sk));

    ASSERT_MEM_EQ(ss_encap, ss_decap, RIVIDE_ML_KEM_SS_BYTES);

    return 0;
}

int test_ml_kem_768_invalid_ct(void) {
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_encap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_decap[RIVIDE_ML_KEM_SS_BYTES];

    ASSERT_OK(rivide_ml_kem_768_keygen(pk, sk));
    ASSERT_OK(rivide_ml_kem_768_encaps(ct, ss_encap, pk));

    /* Tamper with ciphertext. */
    ct[0] ^= 0xFF;

    ASSERT_OK(rivide_ml_kem_768_decaps(ss_decap, ct, sk));

    /* Implicit rejection: shared secret must NOT match. */
    ASSERT_MEM_NE(ss_encap, ss_decap, RIVIDE_ML_KEM_SS_BYTES);

    return 0;
}

int test_ml_kem_1024_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_1024_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_1024_CT_BYTES];
    uint8_t ss_encap[RIVIDE_ML_KEM_SS_BYTES];
    uint8_t ss_decap[RIVIDE_ML_KEM_SS_BYTES];

    ASSERT_OK(rivide_ml_kem_1024_keygen(pk, sk));
    ASSERT_OK(rivide_ml_kem_1024_encaps(ct, ss_encap, pk));
    ASSERT_OK(rivide_ml_kem_1024_decaps(ss_decap, ct, sk));

    ASSERT_MEM_EQ(ss_encap, ss_decap, RIVIDE_ML_KEM_SS_BYTES);

    return 0;
}
