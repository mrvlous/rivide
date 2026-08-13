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
 * @file test_ml_dsa.c
 * @brief Unit tests for NIST FIPS 204 ML-DSA-65 and ML-DSA-87.
 */

#include "rivide/pqc/ml_dsa.h"

#include "test_harness.h"

static const uint8_t test_msg[] = "Rivide Post-Quantum Cryptography Test Message";

int test_ml_dsa_65_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);

    ASSERT_OK(rivide_ml_dsa_65_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_65_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));
    ASSERT_OK(rivide_ml_dsa_65_verify(sig, siglen, test_msg, sizeof(test_msg), pk));

    return 0;
}

int test_ml_dsa_65_tampered_msg(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    uint8_t bad_msg[] = "Rivide Post-Quantum Cryptography Test MessagE";
    size_t siglen = sizeof(sig);

    ASSERT_OK(rivide_ml_dsa_65_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_65_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, siglen, bad_msg, sizeof(bad_msg), pk));

    return 0;
}

int test_ml_dsa_87_roundtrip(void) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = sizeof(sig);

    ASSERT_OK(rivide_ml_dsa_87_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_87_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));
    ASSERT_OK(rivide_ml_dsa_87_verify(sig, siglen, test_msg, sizeof(test_msg), pk));

    return 0;
}
