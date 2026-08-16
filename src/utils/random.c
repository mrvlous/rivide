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
 * @file random.c
 * @brief Platform-dispatched cryptographically secure random byte generation.
 *
 * Provides implementations for Linux (getrandom), Windows (BCryptGenRandom),
 * BSD (getentropy), and thread-safe atomic user-registered RNG callbacks.
 */

#include "rivide/utils/random.h"

#include "rivide/rivide_config.h"

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
typedef _Atomic(rivide_rng_callback_t) atomic_rng_callback_t;
#define RIVIDE_ATOMIC_STORE_RNG(dst, val) atomic_store_explicit(&(dst), (val), memory_order_release)
#define RIVIDE_ATOMIC_LOAD_RNG(src) atomic_load_explicit(&(src), memory_order_acquire)
#elif defined(__GNUC__) || defined(__clang__)
typedef rivide_rng_callback_t atomic_rng_callback_t;
#define RIVIDE_ATOMIC_STORE_RNG(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELEASE)
#define RIVIDE_ATOMIC_LOAD_RNG(src) __atomic_load_n(&(src), __ATOMIC_ACQUIRE)
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
typedef rivide_rng_callback_t atomic_rng_callback_t;
#define RIVIDE_ATOMIC_STORE_RNG(dst, val) \
    ((void)InterlockedExchangePointer((PVOID volatile *)&(dst), (PVOID)(val)))
#define RIVIDE_ATOMIC_LOAD_RNG(src) \
    ((rivide_rng_callback_t)InterlockedCompareExchangePointer((PVOID volatile *)&(src), NULL, NULL))
#else
typedef volatile rivide_rng_callback_t atomic_rng_callback_t;
#define RIVIDE_ATOMIC_STORE_RNG(dst, val) ((dst) = (val))
#define RIVIDE_ATOMIC_LOAD_RNG(src) (src)
#endif

/** @brief User-registered RNG callback stored atomically for thread-safety. */
static atomic_rng_callback_t g_rng_callback = (rivide_rng_callback_t)0;

rivide_status_t rivide_set_rng_callback(rivide_rng_callback_t callback) {
    if (!callback) {
        return RIVIDE_ERR_NULL_PTR;
    }
    RIVIDE_ATOMIC_STORE_RNG(g_rng_callback, callback);
    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_set_randombytes(rivide_rng_callback_t callback) {
    return rivide_set_rng_callback(callback);
}

#if defined(RIVIDE_PLATFORM_LINUX)

#include <errno.h>
#include <sys/random.h>

/**
 * @brief Linux implementation using getrandom(2).
 *
 * Loops until all requested bytes are filled, handling partial reads
 * and signal interruptions (EINTR/EAGAIN) from the kernel entropy pool.
 */
static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t ret = getrandom(buf, len, 0);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return RIVIDE_ERR_RNG_FAILURE;
        }
        buf += (size_t)ret;
        len -= (size_t)ret;
    }
    return RIVIDE_SUCCESS;
}

#elif defined(RIVIDE_PLATFORM_MACOS)

#include <sys/random.h>

/**
 * @brief macOS implementation using getentropy(2).
 *
 * Available since macOS 10.12 Sierra. Limited to 256 bytes per call,
 * so larger requests are chunked automatically.
 */
static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    while (len > 0) {
        size_t chunk = (len > 256) ? 256 : len;
        if (getentropy(buf, chunk) != 0) {
            return RIVIDE_ERR_RNG_FAILURE;
        }
        buf += chunk;
        len -= chunk;
    }
    return RIVIDE_SUCCESS;
}

#elif defined(RIVIDE_PLATFORM_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#if !defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        return RIVIDE_ERR_RNG_FAILURE;
    }
    return RIVIDE_SUCCESS;
}

#elif defined(RIVIDE_PLATFORM_BSD)

#include <unistd.h>

/**
 * @brief BSD implementation using getentropy(2).
 *
 * getentropy is limited to 256 bytes per call, so we loop for larger requests.
 */
static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    while (len > 0) {
        size_t chunk = (len > 256) ? 256 : len;
        if (getentropy(buf, chunk) != 0) {
            return RIVIDE_ERR_RNG_FAILURE;
        }
        buf += chunk;
        len -= chunk;
    }
    return RIVIDE_SUCCESS;
}

#else

/**
 * @brief Freestanding / bare-metal stub.
 *
 * On platforms without a detected OS, this function always returns
 * @ref RIVIDE_ERR_RNG_FAILURE unless a user callback has been registered.
 */
static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    (void)buf;
    (void)len;
    return RIVIDE_ERR_RNG_FAILURE;
}

#endif

rivide_status_t rivide_randombytes(uint8_t *buf, size_t len) {
    rivide_rng_callback_t cb;

    if (!buf && len > 0) {
        return RIVIDE_ERR_NULL_PTR;
    }

    if (len == 0) {
        return RIVIDE_SUCCESS;
    }

    /* Load user callback atomically to ensure thread safety without data races.
     */
    cb = RIVIDE_ATOMIC_LOAD_RNG(g_rng_callback);
    if (cb) {
        return cb(buf, len);
    }

    return rivide_os_randombytes(buf, len);
}
