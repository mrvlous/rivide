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
 * @file rivide_types.h
 * @brief Core type definitions, fixed-width integer aliases, and error codes.
 *
 * This header provides the fundamental types used throughout the Rivide library,
 * including a status/error code enumeration with descriptive string mappings.
 * All public API functions return @ref rivide_status_t to indicate success or
 * the specific failure condition.
 */

#ifndef RIVIDE_TYPES_H
#define RIVIDE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Status codes returned by all public Rivide API functions.
 *
 * A return value of @ref RIVIDE_SUCCESS (0) indicates that the operation
 * completed without error. All error codes are negative integers.
 */
typedef enum rivide_status {
    /** @brief Operation completed successfully. */
    RIVIDE_SUCCESS = 0,

    /** @brief A required pointer argument was NULL. */
    RIVIDE_ERR_NULL_PTR = -1,

    /** @brief An argument value was out of the acceptable range. */
    RIVIDE_ERR_INVALID_PARAM = -2,

    /** @brief The random number generator failed to produce entropy. */
    RIVIDE_ERR_RNG_FAILURE = -3,

    /** @brief Digital signature verification failed. */
    RIVIDE_ERR_VERIFICATION_FAILED = -4,

    /** @brief KEM decapsulation failed (implicit rejection triggered). */
    RIVIDE_ERR_DECAPSULATION_FAILED = -5,

    /** @brief The requested feature or algorithm is not compiled in. */
    RIVIDE_ERR_UNSUPPORTED = -6,

    /** @brief An internal error occurred (should not happen in normal use). */
    RIVIDE_ERR_INTERNAL = -7
} rivide_status_t;

/**
 * @brief Convert a status code to a human-readable string.
 *
 * @param[in] status The status code to convert.
 * @return A pointer to a static, null-terminated string describing the status.
 *         The returned pointer is valid for the lifetime of the program.
 */
const char *rivide_status_str(rivide_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_TYPES_H */
