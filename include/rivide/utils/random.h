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
 * @file random.h
 * @brief Cryptographically secure random byte generation interface.
 *
 * Provides a portable API for obtaining cryptographic-quality entropy.
 * On hosted platforms (Linux, Windows, BSD), the implementation dispatches
 * to the appropriate OS-provided CSPRNG. On freestanding/bare-metal targets,
 * the caller can register an RNG callback via @ref rivide_set_rng_callback or
 * @ref rivide_set_randombytes before invoking any key generation or encapsulation.
 *
 * Thread-Safety Model:
 * - All entropy generation routines (@ref rivide_randombytes) are thread-safe and re-entrant.
 * - Custom RNG callback registration is synchronized atomically via C11 stdatomic
 *   (release-acquire memory ordering) to eliminate data races in multi-threaded
 *   runtime environments (e.g. Rust Rayon, Node.js Worker Threads, Go cgo, POSIX pthreads).
 */

#ifndef RIVIDE_UTILS_RANDOM_H
#define RIVIDE_UTILS_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/rivide_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function pointer type for user-provided random byte generators.
 *
 * The callback must fill exactly @p len bytes of cryptographically secure
 * random data into the buffer pointed to by @p buf.
 *
 * @param[out] buf  Buffer to fill with random bytes.
 * @param[in]  len  Number of bytes to generate.
 *
 * @return @ref RIVIDE_SUCCESS on success, or an appropriate error code.
 */
typedef rivide_status_t (*rivide_rng_callback_t)(uint8_t *buf, size_t len);

/**
 * @brief Register a custom random number generator callback (Thread-Safe Atomic).
 *
 * This function is intended for bare-metal, testing, or custom hardware environments.
 * The registered callback is stored atomically and used by @ref rivide_randombytes
 * for all subsequent calls across all threads.
 *
 * @param[in] callback  Pointer to the RNG callback function.
 *
 * @return @ref RIVIDE_SUCCESS on success, or @ref RIVIDE_ERR_NULL_PTR if
 *         @p callback is NULL.
 */
rivide_status_t rivide_set_rng_callback(rivide_rng_callback_t callback);

/**
 * @brief Alias for @ref rivide_set_rng_callback (Thread-Safe Atomic).
 *
 * @param[in] callback  Pointer to the RNG callback function.
 *
 * @return @ref RIVIDE_SUCCESS on success, or @ref RIVIDE_ERR_NULL_PTR if
 *         @p callback is NULL.
 */
rivide_status_t rivide_set_randombytes(rivide_rng_callback_t callback);

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * On Linux, this calls getrandom(2). On Windows, it uses BCryptGenRandom.
 * On BSD, it uses getentropy(2) or arc4random_buf. On bare-metal or custom setups,
 * it dispatches atomically to the user-registered callback.
 *
 * @param[out] buf  Buffer to fill with random bytes. Must not be NULL.
 * @param[in]  len  Number of bytes to generate.
 *
 * @return @ref RIVIDE_SUCCESS on success.
 * @return @ref RIVIDE_ERR_NULL_PTR if @p buf is NULL.
 * @return @ref RIVIDE_ERR_RNG_FAILURE if the entropy source is unavailable.
 */
rivide_status_t rivide_randombytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RIVIDE_UTILS_RANDOM_H */
