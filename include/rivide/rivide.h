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
 * @file rivide.h
 * @brief Master unified include header for the Rivide Post-Quantum Cryptography library.
 *
 * Including this single header provides access to all public Rivide cryptographic APIs.
 * Individual module headers may also be included directly for finer-grained
 * control over compilation dependencies.
 */

#ifndef RIVIDE_H
#define RIVIDE_H

/** @brief Major version number. */
#define RIVIDE_VERSION_MAJOR 1

/** @brief Minor version number. */
#define RIVIDE_VERSION_MINOR 0

/** @brief Patch version number. */
#define RIVIDE_VERSION_PATCH 0

/** @brief Full version string. */
#define RIVIDE_VERSION_STRING "1.0.0"

#include "crypto/sha3.h"
#include "rivide_config.h"
#include "rivide_types.h"
#include "utils/mem.h"
#include "utils/random.h"

#if RIVIDE_ENABLE_AES_GCM
#include "crypto/aes_gcm.h"
#endif

#if RIVIDE_ENABLE_ML_KEM
#include "pqc/ml_kem.h"
#endif

#if RIVIDE_ENABLE_ML_DSA
#include "pqc/ml_dsa.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the Rivide library.
 *
 * Performs runtime CPU feature detection and sets internal flags used to
 * select optimized code paths (e.g., AES-NI, ARM CE). This function is
 * safe to call multiple times; subsequent calls are no-ops.
 *
 * @return @ref RIVIDE_SUCCESS on success.
 */
rivide_status_t rivide_init(void);

/**
 * @brief Retrieve the library version as a human-readable string.
 *
 * @return A pointer to a static, null-terminated version string
 *         (e.g., "0.4.0"). Valid for the lifetime of the program.
 */
const char *rivide_version_string(void);

/**
 * @brief Retrieve detected CPU feature flags.
 *
 * Returns a bitmask representing detected hardware acceleration features:
 * Bit 0 (0x01): AES-NI available
 * Bit 1 (0x02): ARM Crypto Extensions available
 * Bit 2 (0x04): AVX2 SIMD available
 * Bit 3 (0x08): ARM NEON SIMD available
 *
 * @return Bitmask of detected CPU acceleration features.
 */
uint32_t rivide_get_cpu_features(void);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_H */
