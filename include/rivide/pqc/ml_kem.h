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
 * @file ml_kem.h
 * @brief ML-KEM (NIST FIPS 203) Key Encapsulation Mechanism.
 *
 * Implements the Module-Lattice-Based Key Encapsulation Mechanism standardized
 * in FIPS 203, supporting ML-KEM-768 (Category 3, AES-192 equivalent) and
 * ML-KEM-1024 (Category 5, AES-256 equivalent).
 *
 * ML-KEM provides IND-CCA2 secure key encapsulation based on the hardness of
 * the Module Learning With Errors (MLWE) problem. It uses the NTT over the
 * polynomial ring Z_q[X]/(X^256 + 1) with q = 3329.
 *
 * All buffers are caller-allocated with sizes defined by the parameter-set
 * macros below. No dynamic memory allocation is performed.
 */

#ifndef RIVIDE_PQC_ML_KEM_H
#define RIVIDE_PQC_ML_KEM_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/rivide_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup ml_kem_common Common ML-KEM Parameters
 * @brief Parameters shared across all ML-KEM parameter sets.
 * @{
 */

/** @brief Polynomial degree n = 256. */
#define RIVIDE_ML_KEM_N 256

/** @brief Modulus q = 3329. */
#define RIVIDE_ML_KEM_Q 3329

/** @brief Shared secret length in bytes. */
#define RIVIDE_ML_KEM_SS_BYTES 32

/** @} */

/**
 * @defgroup ml_kem_768 ML-KEM-768 Parameters
 * @brief Parameter set for NIST Security Category 3.
 * @{
 */

/** @brief Module rank k = 3. */
#define RIVIDE_ML_KEM_768_K 3

/** @brief Encapsulation (public) key size in bytes. */
#define RIVIDE_ML_KEM_768_PK_BYTES 1184

/** @brief Decapsulation (secret) key size in bytes. */
#define RIVIDE_ML_KEM_768_SK_BYTES 2400

/** @brief Ciphertext size in bytes. */
#define RIVIDE_ML_KEM_768_CT_BYTES 1088

/** @brief CBD eta_1 parameter for secret vector sampling. */
#define RIVIDE_ML_KEM_768_ETA1 2

/** @brief CBD eta_2 parameter for noise vector sampling. */
#define RIVIDE_ML_KEM_768_ETA2 2

/** @brief Compression parameter d_u for ciphertext vector u. */
#define RIVIDE_ML_KEM_768_DU 10

/** @brief Compression parameter d_v for ciphertext scalar v. */
#define RIVIDE_ML_KEM_768_DV 4

/** @} */

/**
 * @defgroup ml_kem_1024 ML-KEM-1024 Parameters
 * @brief Parameter set for NIST Security Category 5.
 * @{
 */

/** @brief Module rank k = 4. */
#define RIVIDE_ML_KEM_1024_K 4

/** @brief Encapsulation (public) key size in bytes. */
#define RIVIDE_ML_KEM_1024_PK_BYTES 1568

/** @brief Decapsulation (secret) key size in bytes. */
#define RIVIDE_ML_KEM_1024_SK_BYTES 3168

/** @brief Ciphertext size in bytes. */
#define RIVIDE_ML_KEM_1024_CT_BYTES 1568

/** @brief CBD eta_1 parameter. */
#define RIVIDE_ML_KEM_1024_ETA1 2

/** @brief CBD eta_2 parameter. */
#define RIVIDE_ML_KEM_1024_ETA2 2

/** @brief Compression parameter d_u. */
#define RIVIDE_ML_KEM_1024_DU 11

/** @brief Compression parameter d_v. */
#define RIVIDE_ML_KEM_1024_DV 5

/** @} */

/**
 * @brief Generate an ML-KEM-768 key pair.
 *
 * @param[out] pk  Encapsulation key buffer (1184 bytes).
 * @param[out] sk  Decapsulation key buffer (2400 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 * @return @ref RIVIDE_ERR_NULL_PTR if any pointer is NULL.
 * @return @ref RIVIDE_ERR_RNG_FAILURE if the entropy source fails.
 */
rivide_status_t rivide_ml_kem_768_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate a shared secret using ML-KEM-768.
 *
 * @param[out] ct  Ciphertext buffer (1088 bytes).
 * @param[out] ss  Shared secret buffer (32 bytes).
 * @param[in]  pk  Encapsulation key (1184 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 * @return @ref RIVIDE_ERR_NULL_PTR if any pointer is NULL.
 * @return @ref RIVIDE_ERR_RNG_FAILURE if the entropy source fails.
 */
rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate a shared secret using ML-KEM-768.
 *
 * Implements implicit rejection: if the ciphertext is invalid, a
 * pseudorandom value derived from the secret key is returned instead
 * of an error, preventing chosen-ciphertext attacks.
 *
 * @param[out] ss  Shared secret buffer (32 bytes).
 * @param[in]  ct  Ciphertext (1088 bytes).
 * @param[in]  sk  Decapsulation key (2400 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 * @return @ref RIVIDE_ERR_NULL_PTR if any pointer is NULL.
 */
rivide_status_t rivide_ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/**
 * @brief Generate an ML-KEM-1024 key pair.
 *
 * @param[out] pk  Encapsulation key buffer (1568 bytes).
 * @param[out] sk  Decapsulation key buffer (3168 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_kem_1024_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate a shared secret using ML-KEM-1024.
 *
 * @param[out] ct  Ciphertext buffer (1568 bytes).
 * @param[out] ss  Shared secret buffer (32 bytes).
 * @param[in]  pk  Encapsulation key (1568 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate a shared secret using ML-KEM-1024.
 *
 * @param[out] ss  Shared secret buffer (32 bytes).
 * @param[in]  ct  Ciphertext (1568 bytes).
 * @param[in]  sk  Decapsulation key (3168 bytes).
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_PQC_ML_KEM_H */
