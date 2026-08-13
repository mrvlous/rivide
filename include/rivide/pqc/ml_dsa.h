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
 * @file ml_dsa.h
 * @brief ML-DSA (NIST FIPS 204) Digital Signature Algorithm.
 *
 * Implements the Module-Lattice-Based Digital Signature Algorithm standardized
 * in FIPS 204, supporting ML-DSA-65 (Category 3, AES-192 equivalent) and
 * ML-DSA-87 (Category 5, AES-256 equivalent).
 *
 * ML-DSA provides EUF-CMA secure digital signatures based on the hardness
 * of the Module Short Integer Solution (MSIS) and Module Learning With Errors
 * (MLWE) problems. It operates over Z_q[X]/(X^256 + 1) with q = 8380417.
 */

#ifndef RIVIDE_PQC_ML_DSA_H
#define RIVIDE_PQC_ML_DSA_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/rivide_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup ml_dsa_common Common ML-DSA Parameters
 * @{
 */

/** @brief Polynomial degree n = 256. */
#define RIVIDE_ML_DSA_N 256

/** @brief Modulus q = 8380417 = 2^23 - 2^13 + 1. */
#define RIVIDE_ML_DSA_Q 8380417

/** @brief Number of ones in the challenge polynomial c. */
#define RIVIDE_ML_DSA_TAU_65 49
#define RIVIDE_ML_DSA_TAU_87 60

/** @brief Seed/hash output length for tr (hash of public key). */
#define RIVIDE_ML_DSA_SEEDBYTES 32
#define RIVIDE_ML_DSA_TRBYTES 64

/** @} */

/**
 * @defgroup ml_dsa_65 ML-DSA-65 Parameters
 * @brief Parameter set for NIST Security Category 3.
 * @{
 */

/** @brief Matrix dimensions (k, l) = (6, 5). */
#define RIVIDE_ML_DSA_65_K 6
#define RIVIDE_ML_DSA_65_L 5

/** @brief Public key size in bytes. */
#define RIVIDE_ML_DSA_65_PK_BYTES 1952

/** @brief Secret key size in bytes. */
#define RIVIDE_ML_DSA_65_SK_BYTES 4032

/** @brief Maximum signature size in bytes. */
#define RIVIDE_ML_DSA_65_SIG_BYTES 3309

/** @brief Infinity norm bound for secret vectors (eta). */
#define RIVIDE_ML_DSA_65_ETA 4

/** @brief Rounding parameter gamma1 = 2^19. */
#define RIVIDE_ML_DSA_65_GAMMA1 (1 << 19)

/** @brief Decomposition parameter gamma2 = (q-1)/88. */
#define RIVIDE_ML_DSA_65_GAMMA2 ((RIVIDE_ML_DSA_Q - 1) / 32)

/** @brief Number of dropped bits from t (d = 13). */
#define RIVIDE_ML_DSA_65_D 13

/** @brief Maximum number of ones in the hint vector. */
#define RIVIDE_ML_DSA_65_OMEGA 55

/** @brief Challenge seed bytes (lambda/4). */
#define RIVIDE_ML_DSA_65_CTILDEBYTES 48

/** @} */

/**
 * @defgroup ml_dsa_87 ML-DSA-87 Parameters
 * @brief Parameter set for NIST Security Category 5.
 * @{
 */

/** @brief Matrix dimensions (k, l) = (8, 7). */
#define RIVIDE_ML_DSA_87_K 8
#define RIVIDE_ML_DSA_87_L 7

/** @brief Public key size in bytes. */
#define RIVIDE_ML_DSA_87_PK_BYTES 2592

/** @brief Secret key size in bytes. */
#define RIVIDE_ML_DSA_87_SK_BYTES 4896

/** @brief Maximum signature size in bytes. */
#define RIVIDE_ML_DSA_87_SIG_BYTES 4627

/** @brief Infinity norm bound for secret vectors (eta). */
#define RIVIDE_ML_DSA_87_ETA 2

/** @brief Rounding parameter gamma1 = 2^19. */
#define RIVIDE_ML_DSA_87_GAMMA1 (1 << 19)

/** @brief Decomposition parameter gamma2 = (q-1)/32. */
#define RIVIDE_ML_DSA_87_GAMMA2 ((RIVIDE_ML_DSA_Q - 1) / 32)

/** @brief Number of dropped bits from t (d = 13). */
#define RIVIDE_ML_DSA_87_D 13

/** @brief Maximum number of ones in the hint vector. */
#define RIVIDE_ML_DSA_87_OMEGA 75

/** @brief Challenge seed bytes (lambda/4). */
#define RIVIDE_ML_DSA_87_CTILDEBYTES 64

/** @} */

/**
 * @brief Generate an ML-DSA-65 key pair.
 *
 * @param[out] pk  Public key buffer (1952 bytes).
 * @param[out] sk  Secret key buffer (4032 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Sign a message with ML-DSA-65.
 *
 * The signature is produced via rejection sampling, which means the
 * signing time is variable but bounded in expectation.
 *
 * @param[out]    sig     Signature buffer (up to 3309 bytes).
 * @param[in,out] siglen  On input, size of sig buffer. On output, actual
 *                        signature length.
 * @param[in]     msg     Message to sign.
 * @param[in]     msglen  Length of the message in bytes.
 * @param[in]     sk      Secret key (4032 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_dsa_65_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk);

/**
 * @brief Verify an ML-DSA-65 signature.
 *
 * @param[in] sig     Signature to verify.
 * @param[in] siglen  Length of the signature in bytes.
 * @param[in] msg     Message that was signed.
 * @param[in] msglen  Length of the message in bytes.
 * @param[in] pk      Public key (1952 bytes).
 *
 * @return @ref RIVIDE_SUCCESS if the signature is valid.
 * @return @ref RIVIDE_ERR_VERIFICATION_FAILED if the signature is invalid.
 */
rivide_status_t rivide_ml_dsa_65_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk);

/**
 * @brief Generate an ML-DSA-87 key pair.
 *
 * @param[out] pk  Public key buffer (2592 bytes).
 * @param[out] sk  Secret key buffer (4896 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_dsa_87_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Sign a message with ML-DSA-87.
 *
 * @param[out]    sig     Signature buffer (up to 4627 bytes).
 * @param[in,out] siglen  On input, buffer size. On output, actual length.
 * @param[in]     msg     Message to sign.
 * @param[in]     msglen  Length of the message in bytes.
 * @param[in]     sk      Secret key (4896 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_dsa_87_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk);

/**
 * @brief Verify an ML-DSA-87 signature.
 *
 * @param[in] sig     Signature to verify.
 * @param[in] siglen  Length of the signature in bytes.
 * @param[in] msg     Message that was signed.
 * @param[in] msglen  Length of the message in bytes.
 * @param[in] pk      Public key (2592 bytes).
 *
 * @return @ref RIVIDE_SUCCESS if the signature is valid.
 * @return @ref RIVIDE_ERR_VERIFICATION_FAILED if invalid.
 */
rivide_status_t rivide_ml_dsa_87_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_PQC_ML_DSA_H */
