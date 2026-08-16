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
 * @file rivide_init.c
 * @brief Core library initialization and runtime feature detection.
 *
 * Provides thread-safe atomic initialization and CPU hardware feature probing.
 */

#include "rivide/rivide.h"
#include "rivide/rivide_config.h"

#if defined(RIVIDE_PLATFORM_MACOS) && defined(RIVIDE_ARCH_ARM64)
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
typedef atomic_int atomic_init_flag_t;
typedef atomic_uint_fast32_t atomic_cpu_features_t;
#define RIVIDE_ATOMIC_LOAD_INT(src) atomic_load_explicit(&(src), memory_order_acquire)
#define RIVIDE_ATOMIC_STORE_INT(dst, val) atomic_store_explicit(&(dst), (val), memory_order_release)
#define RIVIDE_ATOMIC_CAS_INT(dst, exp, des)                                             \
    atomic_compare_exchange_strong_explicit(&(dst), &(exp), (des), memory_order_acq_rel, \
                                            memory_order_acquire)
#define RIVIDE_ATOMIC_LOAD_UINT32(src) atomic_load_explicit(&(src), memory_order_acquire)
#define RIVIDE_ATOMIC_STORE_UINT32(dst, val) \
    atomic_store_explicit(&(dst), (val), memory_order_release)
#elif defined(__GNUC__) || defined(__clang__)
typedef int atomic_init_flag_t;
typedef uint32_t atomic_cpu_features_t;
#define RIVIDE_ATOMIC_LOAD_INT(src) __atomic_load_n(&(src), __ATOMIC_ACQUIRE)
#define RIVIDE_ATOMIC_STORE_INT(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELEASE)
#define RIVIDE_ATOMIC_CAS_INT(dst, exp, des) \
    __atomic_compare_exchange_n(&(dst), &(exp), (des), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#define RIVIDE_ATOMIC_LOAD_UINT32(src) __atomic_load_n(&(src), __ATOMIC_ACQUIRE)
#define RIVIDE_ATOMIC_STORE_UINT32(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELEASE)
#elif defined(_MSC_VER)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
typedef volatile LONG atomic_init_flag_t;
typedef volatile LONG atomic_cpu_features_t;
#define RIVIDE_ATOMIC_LOAD_INT(src) InterlockedCompareExchange((LONG volatile *)&(src), 0, 0)
#define RIVIDE_ATOMIC_STORE_INT(dst, val) \
    ((void)InterlockedExchange((LONG volatile *)&(dst), (LONG)(val)))
static inline int rivide_msvc_cas_int(atomic_init_flag_t *dst, int exp, int des) {
    return (InterlockedCompareExchange((LONG volatile *)dst, (LONG)des, (LONG)exp) == (LONG)exp);
}
#define RIVIDE_ATOMIC_CAS_INT(dst, exp, des) rivide_msvc_cas_int(&(dst), (exp), (des))
#define RIVIDE_ATOMIC_LOAD_UINT32(src) \
    ((uint32_t)InterlockedCompareExchange((LONG volatile *)&(src), 0, 0))
#define RIVIDE_ATOMIC_STORE_UINT32(dst, val) \
    ((void)InterlockedExchange((LONG volatile *)&(dst), (LONG)(val)))
#else
typedef volatile int atomic_init_flag_t;
typedef volatile uint32_t atomic_cpu_features_t;
#define RIVIDE_ATOMIC_LOAD_INT(src) (src)
#define RIVIDE_ATOMIC_STORE_INT(dst, val) ((dst) = (val))
static inline int rivide_fallback_cas_int(atomic_init_flag_t *dst, int exp, int des) {
    if (*dst == exp) {
        *dst = des;
        return 1;
    }
    return 0;
}
#define RIVIDE_ATOMIC_CAS_INT(dst, exp, des) rivide_fallback_cas_int(&(dst), (exp), (des))
#define RIVIDE_ATOMIC_LOAD_UINT32(src) (src)
#define RIVIDE_ATOMIC_STORE_UINT32(dst, val) ((dst) = (val))
#endif

/** @brief Tracks initialization state: 0 = uninit, 1 = initializing, 2 = initialized. */
static atomic_init_flag_t g_rivide_init_state = 0;

/**
 * @brief Runtime CPU feature flags, populated once by rivide_init().
 *
 * Bit 0: AES-NI / AES hardware acceleration available
 * Bit 1: ARM Crypto Extensions available
 * Bit 2: AVX2 SIMD available
 * Bit 3: ARM NEON SIMD available
 */
static atomic_cpu_features_t g_rivide_cpu_features = 0;

#if defined(RIVIDE_ARCH_X86_64) || defined(RIVIDE_ARCH_X86)

/**
 * @brief Execute CPUID instruction on x86/x86_64.
 *
 * @param[in]  leaf  The CPUID leaf (EAX input).
 * @param[out] eax   Output EAX register value.
 * @param[out] ebx   Output EBX register value.
 * @param[out] ecx   Output ECX register value.
 * @param[out] edx   Output EDX register value.
 */
static void rivide_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                         uint32_t *edx) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(leaf), "c"(0));
#elif defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, (int)leaf);
    *eax = (uint32_t)regs[0];
    *ebx = (uint32_t)regs[1];
    *ecx = (uint32_t)regs[2];
    *edx = (uint32_t)regs[3];
#else
    *eax = *ebx = *ecx = *edx = 0;
#endif
}

/**
 * @brief Detect x86 CPU features via CPUID.
 *
 * Probes CPUID leaf 1 for AES-NI and leaf 7 for AVX2 support.
 */
static uint32_t rivide_detect_x86_features(void) {
    uint32_t eax, ebx, ecx, edx;
    uint32_t feats = 0;

    /* Leaf 1: ECX bit 25 = AES-NI */
    rivide_cpuid(1, &eax, &ebx, &ecx, &edx);
    if (ecx & (1u << 25)) {
        feats |= 0x01u;
    }

    /* Leaf 7, sub-leaf 0: EBX bit 5 = AVX2 */
    rivide_cpuid(7, &eax, &ebx, &ecx, &edx);
    if (ebx & (1u << 5)) {
        feats |= 0x04u;
    }

    return feats;
}

#elif defined(RIVIDE_ARCH_ARM64)

/**
 * @brief Detect ARM64 CPU features.
 *
 * On macOS Apple Silicon, uses sysctlbyname to query hardware capabilities.
 * On Linux ARM64, reads /proc/cpuinfo flags or uses compile-time detection.
 */
static uint32_t rivide_detect_arm64_features(void) {
    uint32_t feats = 0;

#if defined(RIVIDE_PLATFORM_MACOS)
    int64_t val = 0;
    size_t size = sizeof(val);

    /* Query AES hardware acceleration */
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &val, &size, NULL, 0) == 0 && val) {
        feats |= 0x02u;
    }

    /* ARM NEON is always available on Apple Silicon */
    feats |= 0x08u;
#else
    /* Linux ARM64: use compile-time feature macros */
#if defined(__ARM_FEATURE_CRYPTO)
    feats |= 0x02u;
#endif
#if defined(__ARM_NEON)
    feats |= 0x08u;
#endif
#endif /* RIVIDE_PLATFORM_MACOS */

    return feats;
}

#endif /* architecture */

rivide_status_t rivide_init(void) {
    int state = (int)RIVIDE_ATOMIC_LOAD_INT(g_rivide_init_state);
    if (state == 2) {
        return RIVIDE_SUCCESS;
    }

    int exp = 0;
    if (RIVIDE_ATOMIC_CAS_INT(g_rivide_init_state, exp, 1)) {
        uint32_t feats = 0;
#if defined(RIVIDE_ARCH_X86_64) || defined(RIVIDE_ARCH_X86)
        feats = rivide_detect_x86_features();
#elif defined(RIVIDE_ARCH_ARM64)
        feats = rivide_detect_arm64_features();
#endif
        RIVIDE_ATOMIC_STORE_UINT32(g_rivide_cpu_features, feats);
        RIVIDE_ATOMIC_STORE_INT(g_rivide_init_state, 2);
        return RIVIDE_SUCCESS;
    }

    while ((int)RIVIDE_ATOMIC_LOAD_INT(g_rivide_init_state) != 2) {
        /* Spin until initialization is marked complete by the winning thread. */
    }

    return RIVIDE_SUCCESS;
}

const char *rivide_version_string(void) {
    return RIVIDE_VERSION_STRING;
}

uint32_t rivide_get_cpu_features(void) {
    return (uint32_t)RIVIDE_ATOMIC_LOAD_UINT32(g_rivide_cpu_features);
}
