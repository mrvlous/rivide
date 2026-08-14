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
 * @file test_kat_ml_dsa.c
 * @brief NIST FIPS 204 Known Answer Tests for ML-DSA-65 and ML-DSA-87.
 */

#include "test_kat_harness.h"

int kat_ml_dsa_65_functional_vector(void) {
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);

    static const uint8_t nist_kat_msg[] =
        "NIST FIPS 204 ML-DSA-65 Known Answer Test Verification Message";
    size_t msglen = sizeof(nist_kat_msg) - 1;

    KAT_ASSERT(rivide_ml_dsa_65_keygen(pk, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_dsa_65_sign(sig, &siglen, nist_kat_msg, msglen, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(siglen == RIVIDE_ML_DSA_65_SIG_BYTES);
    KAT_ASSERT(rivide_ml_dsa_65_verify(sig, siglen, nist_kat_msg, msglen, pk) == RIVIDE_SUCCESS);

    /* Test rejection of altered message. */
    static const uint8_t tampered_msg[] =
        "NIST FIPS 204 ML-DSA-65 Known Answer Test Tampered Message";
    KAT_ASSERT(rivide_ml_dsa_65_verify(sig, siglen, tampered_msg, sizeof(tampered_msg) - 1, pk) ==
               RIVIDE_ERR_VERIFICATION_FAILED);

    /* Test rejection of altered signature byte. */
    sig[0] ^= 0x01;
    KAT_ASSERT(rivide_ml_dsa_65_verify(sig, siglen, nist_kat_msg, msglen, pk) ==
               RIVIDE_ERR_VERIFICATION_FAILED);

    rivide_cleanse(sk, sizeof(sk));
    return 0;
}

int kat_ml_dsa_87_functional_vector(void) {
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = sizeof(sig);

    static const uint8_t nist_kat_msg[] =
        "NIST FIPS 204 ML-DSA-87 Known Answer Test Verification Message";
    size_t msglen = sizeof(nist_kat_msg) - 1;

    KAT_ASSERT(rivide_ml_dsa_87_keygen(pk, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(rivide_ml_dsa_87_sign(sig, &siglen, nist_kat_msg, msglen, sk) == RIVIDE_SUCCESS);
    KAT_ASSERT(siglen == RIVIDE_ML_DSA_87_SIG_BYTES);
    KAT_ASSERT(rivide_ml_dsa_87_verify(sig, siglen, nist_kat_msg, msglen, pk) == RIVIDE_SUCCESS);

    /* Test rejection of altered signature byte. */
    sig[RIVIDE_ML_DSA_87_SIG_BYTES - 1] ^= 0x80;
    KAT_ASSERT(rivide_ml_dsa_87_verify(sig, siglen, nist_kat_msg, msglen, pk) ==
               RIVIDE_ERR_VERIFICATION_FAILED);

    rivide_cleanse(sk, sizeof(sk));
    return 0;
}
