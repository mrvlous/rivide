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
 * @brief Unit tests and security regression tests for NIST FIPS 204 ML-DSA.
 */

#include <string.h>

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

int test_ml_dsa_65_siglen_validation(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES + 64];
    size_t siglen = RIVIDE_ML_DSA_65_SIG_BYTES;

    ASSERT_OK(rivide_ml_dsa_65_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_65_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));
    ASSERT_EQ(siglen, RIVIDE_ML_DSA_65_SIG_BYTES);

    /* Test 0 length. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, 0, test_msg, sizeof(test_msg), pk));

    /* Test small lengths. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, 1, test_msg, sizeof(test_msg), pk));
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, 2, test_msg, sizeof(test_msg), pk));

    /* Test expected - 1 length. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, RIVIDE_ML_DSA_65_SIG_BYTES - 1, test_msg,
                                        sizeof(test_msg), pk));

    /* Test exact expected length (must pass). */
    ASSERT_OK(
        rivide_ml_dsa_65_verify(sig, RIVIDE_ML_DSA_65_SIG_BYTES, test_msg, sizeof(test_msg), pk));

    /* Test expected + 1 length. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, RIVIDE_ML_DSA_65_SIG_BYTES + 1, test_msg,
                                        sizeof(test_msg), pk));

    /* Test expected + 32 length. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, RIVIDE_ML_DSA_65_SIG_BYTES + 32, test_msg,
                                        sizeof(test_msg), pk));

    return 0;
}

int test_ml_dsa_87_siglen_validation(void) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES + 64];
    size_t siglen = RIVIDE_ML_DSA_87_SIG_BYTES;

    ASSERT_OK(rivide_ml_dsa_87_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_87_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));
    ASSERT_EQ(siglen, RIVIDE_ML_DSA_87_SIG_BYTES);

    /* Test 0 length. */
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, 0, test_msg, sizeof(test_msg), pk));

    /* Test small lengths. */
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, 1, test_msg, sizeof(test_msg), pk));
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, 2, test_msg, sizeof(test_msg), pk));

    /* Test expected - 1 length. */
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, RIVIDE_ML_DSA_87_SIG_BYTES - 1, test_msg,
                                        sizeof(test_msg), pk));

    /* Test exact expected length (must pass). */
    ASSERT_OK(
        rivide_ml_dsa_87_verify(sig, RIVIDE_ML_DSA_87_SIG_BYTES, test_msg, sizeof(test_msg), pk));

    /* Test expected + 1 length. */
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, RIVIDE_ML_DSA_87_SIG_BYTES + 1, test_msg,
                                        sizeof(test_msg), pk));

    /* Test expected + 32 length. */
    ASSERT_FAIL(rivide_ml_dsa_87_verify(sig, RIVIDE_ML_DSA_87_SIG_BYTES + 32, test_msg,
                                        sizeof(test_msg), pk));

    return 0;
}

int test_ml_dsa_boundary_fuzz(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    uint8_t corrupt_sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    uint8_t corrupt_pk[RIVIDE_ML_DSA_65_PK_BYTES];
    size_t siglen = sizeof(sig);

    ASSERT_OK(rivide_ml_dsa_65_keygen(pk, sk));
    ASSERT_OK(rivide_ml_dsa_65_sign(sig, &siglen, test_msg, sizeof(test_msg), sk));

    /* NULL pointer tests. */
    ASSERT_FAIL(rivide_ml_dsa_65_verify(NULL, siglen, test_msg, sizeof(test_msg), pk));
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, siglen, NULL, sizeof(test_msg), pk));
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, siglen, test_msg, sizeof(test_msg), NULL));

    /* Corrupt challenge seed c_tilde (first 48 bytes). */
    memcpy(corrupt_sig, sig, sizeof(sig));
    corrupt_sig[0] ^= 0x01;
    ASSERT_FAIL(rivide_ml_dsa_65_verify(corrupt_sig, siglen, test_msg, sizeof(test_msg), pk));

    /* Corrupt z polynomial vector (middle section). */
    memcpy(corrupt_sig, sig, sizeof(sig));
    corrupt_sig[100] ^= 0x55;
    ASSERT_FAIL(rivide_ml_dsa_65_verify(corrupt_sig, siglen, test_msg, sizeof(test_msg), pk));

    /* Corrupt hint vector (tail section). */
    memcpy(corrupt_sig, sig, sizeof(sig));
    corrupt_sig[RIVIDE_ML_DSA_65_SIG_BYTES - 1] ^= 0x80;
    ASSERT_FAIL(rivide_ml_dsa_65_verify(corrupt_sig, siglen, test_msg, sizeof(test_msg), pk));

    /* Corrupt public key. */
    memcpy(corrupt_pk, pk, sizeof(pk));
    corrupt_pk[0] ^= 0xFF;
    ASSERT_FAIL(rivide_ml_dsa_65_verify(sig, siglen, test_msg, sizeof(test_msg), corrupt_pk));

    /* Empty message (msglen = 0) valid signature roundtrip. */
    {
        uint8_t zero_sig[RIVIDE_ML_DSA_65_SIG_BYTES];
        size_t zero_siglen = sizeof(zero_sig);
        uint8_t dummy = 0;
        ASSERT_OK(rivide_ml_dsa_65_sign(zero_sig, &zero_siglen, &dummy, 0, sk));
        ASSERT_OK(rivide_ml_dsa_65_verify(zero_sig, zero_siglen, &dummy, 0, pk));
    }

    return 0;
}
