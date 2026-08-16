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
 * @file rivide_config.h
 * @brief Compile-time configuration flags and platform detection macros.
 *
 * This header provides compile-time feature toggles for enabling or disabling
 * individual cryptographic modules, as well as automatic platform and CPU
 * feature detection for selecting optimized code paths.
 */

#ifndef RIVIDE_CONFIG_H
#define RIVIDE_CONFIG_H

/** @brief Major version number. */
#define RIVIDE_VERSION_MAJOR 1

/** @brief Minor version number. */
#define RIVIDE_VERSION_MINOR 1

/** @brief Patch version number. */
#define RIVIDE_VERSION_PATCH 2

/** @brief Complete version string constant. */
#define RIVIDE_VERSION_STRING "1.1.2"

/**
 * @defgroup config_feature_flags Feature Flags
 * @brief Compile-time toggles for cryptographic modules.
 *
 * Define these macros before including any Rivide header, or pass them via
 * compiler flags (e.g., -DRIVIDE_DISABLE_ML_KEM) to selectively exclude
 * modules from the build. All modules are enabled by default.
 * @{
 */

/** @brief Enable ML-KEM (FIPS 203) key encapsulation. Enabled by default. */
#ifndef RIVIDE_DISABLE_ML_KEM
#define RIVIDE_ENABLE_ML_KEM 1
#else
#define RIVIDE_ENABLE_ML_KEM 0
#endif

/** @brief Enable ML-DSA (FIPS 204) digital signatures. Enabled by default. */
#ifndef RIVIDE_DISABLE_ML_DSA
#define RIVIDE_ENABLE_ML_DSA 1
#else
#define RIVIDE_ENABLE_ML_DSA 0
#endif

/** @brief Enable AES-GCM AEAD encryption. Enabled by default. */
#ifndef RIVIDE_DISABLE_AES_GCM
#define RIVIDE_ENABLE_AES_GCM 1
#else
#define RIVIDE_ENABLE_AES_GCM 0
#endif

/** @brief Enable SHA-3 / SHAKE hash functions. Always enabled (required by PQC). */
#define RIVIDE_ENABLE_SHA3 1

/** @} */

/**
 * @defgroup config_platform Platform Detection
 * @brief Automatic detection of target operating system and environment.
 * @{
 */

#if defined(__APPLE__) && defined(__MACH__)
#define RIVIDE_PLATFORM_MACOS 1
#define RIVIDE_PLATFORM_POSIX 1
#elif defined(__linux__)
#define RIVIDE_PLATFORM_LINUX 1
#define RIVIDE_PLATFORM_POSIX 1
#elif defined(_WIN32) || defined(_WIN64)
#define RIVIDE_PLATFORM_WINDOWS 1
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define RIVIDE_PLATFORM_BSD 1
#define RIVIDE_PLATFORM_POSIX 1
#endif

/** @brief Detect freestanding / bare-metal environment. */
#if defined(__STDC_HOSTED__) && (__STDC_HOSTED__ == 0)
#define RIVIDE_FREESTANDING 1
#else
#define RIVIDE_FREESTANDING 0
#endif

/** @} */

/**
 * @defgroup config_arch Architecture Detection
 * @brief Automatic detection of CPU architecture.
 * @{
 */

#if defined(__x86_64__) || defined(_M_X64)
#define RIVIDE_ARCH_X86_64 1
#elif defined(__i386__) || defined(_M_IX86)
#define RIVIDE_ARCH_X86 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#define RIVIDE_ARCH_ARM64 1
#elif defined(__arm__) || defined(_M_ARM)
#define RIVIDE_ARCH_ARM32 1
#elif defined(__riscv)
#define RIVIDE_ARCH_RISCV 1
#endif

/** @} */

/**
 * @defgroup config_hwcap Hardware Capability Detection
 * @brief Compile-time detection of hardware cryptographic acceleration.
 * @{
 */

/** @brief AES-NI intrinsics available on x86/x86_64. */
#if (defined(RIVIDE_ARCH_X86_64) || defined(RIVIDE_ARCH_X86)) && defined(__AES__)
#define RIVIDE_HAS_AESNI 1
#endif

/** @brief ARMv8 Cryptography Extensions. */
#if defined(RIVIDE_ARCH_ARM64) && defined(__ARM_FEATURE_CRYPTO)
#define RIVIDE_HAS_ARM_CE 1
#endif

/** @brief ARM NEON SIMD. */
#if defined(RIVIDE_ARCH_ARM64) || (defined(RIVIDE_ARCH_ARM32) && defined(__ARM_NEON))
#define RIVIDE_HAS_NEON 1
#endif

/** @} */

/**
 * @defgroup config_endian Endianness Detection
 * @brief Compile-time detection of byte order.
 * @{
 */

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RIVIDE_LITTLE_ENDIAN 1
#define RIVIDE_BIG_ENDIAN 0
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define RIVIDE_LITTLE_ENDIAN 0
#define RIVIDE_BIG_ENDIAN 1
#else
#error "Unsupported byte order"
#endif
#elif defined(_WIN32)
/* Windows is always little-endian on supported architectures. */
#define RIVIDE_LITTLE_ENDIAN 1
#define RIVIDE_BIG_ENDIAN 0
#else
/* Default assumption: little-endian. Override if targeting big-endian. */
#define RIVIDE_LITTLE_ENDIAN 1
#define RIVIDE_BIG_ENDIAN 0
#endif

/** @} */

/**
 * @defgroup config_compiler Compiler Helpers
 * @brief Portable compiler attribute macros.
 * @{
 */

#if defined(__GNUC__) || defined(__clang__)
#define RIVIDE_INLINE static inline __attribute__((always_inline))
#define RIVIDE_NOINLINE __attribute__((noinline))
#define RIVIDE_UNUSED __attribute__((unused))
#define RIVIDE_LIKELY(x) __builtin_expect(!!(x), 1)
#define RIVIDE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#elif defined(_MSC_VER)
#define RIVIDE_INLINE static __forceinline
#define RIVIDE_NOINLINE __declspec(noinline)
#define RIVIDE_UNUSED
#define RIVIDE_LIKELY(x) (x)
#define RIVIDE_UNLIKELY(x) (x)
#else
#define RIVIDE_INLINE static inline
#define RIVIDE_NOINLINE
#define RIVIDE_UNUSED
#define RIVIDE_LIKELY(x) (x)
#define RIVIDE_UNLIKELY(x) (x)
#endif

/** @} */

#endif /* RIVIDE_CONFIG_H */
