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
 * BSD (getentropy), and bare-metal (user callback) environments.
 */

#include "rivide/utils/random.h"

#include "rivide/rivide_config.h"

/** @brief User-registered RNG callback, or NULL for OS default. */
static rivide_rng_callback_t g_rng_callback = (rivide_rng_callback_t)0;

rivide_status_t rivide_set_rng_callback(rivide_rng_callback_t callback) {
    if (!callback) {
        return RIVIDE_ERR_NULL_PTR;
    }
    g_rng_callback = callback;
    return RIVIDE_SUCCESS;
}

#if defined(RIVIDE_PLATFORM_LINUX)

#include <sys/random.h>

/**
 * @brief Linux implementation using getrandom(2).
 *
 * Loops until all requested bytes are filled, handling partial reads
 * from the kernel entropy pool.
 */
static rivide_status_t rivide_os_randombytes(uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t ret = getrandom(buf, len, 0);
        if (ret < 0) {
            return RIVIDE_ERR_RNG_FAILURE;
        }
        buf += (size_t)ret;
        len -= (size_t)ret;
    }
    return RIVIDE_SUCCESS;
}

#elif defined(RIVIDE_PLATFORM_WINDOWS)

/*
 * BCryptGenRandom requires linking against bcrypt.lib. This is handled
 * automatically by the pragma on MSVC; other Windows compilers may need
 * explicit linker flags.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <bcrypt.h>
#include <windows.h>
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
    if (!buf && len > 0) {
        return RIVIDE_ERR_NULL_PTR;
    }

    if (len == 0) {
        return RIVIDE_SUCCESS;
    }

    /* Prefer user callback if registered. */
    if (g_rng_callback) {
        return g_rng_callback(buf, len);
    }

    return rivide_os_randombytes(buf, len);
}
