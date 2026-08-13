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
 */

#include "rivide/rivide.h"
#include "rivide/rivide_config.h"

#if defined(RIVIDE_PLATFORM_MACOS) && defined(RIVIDE_ARCH_ARM64)
#include <sys/sysctl.h>
#endif

/** @brief Tracks whether rivide_init() has already been called. */
static volatile int g_rivide_initialized = 0;

/**
 * @brief Runtime CPU feature flags, populated by rivide_init().
 *
 * These flags are set once at initialization and read thereafter.
 * Bit 0: AES-NI / AES hardware acceleration available
 * Bit 1: ARM Crypto Extensions available
 * Bit 2: AVX2 SIMD available
 * Bit 3: ARM NEON SIMD available
 */
static uint32_t g_rivide_cpu_features = 0;

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
static void rivide_detect_x86_features(void) {
    uint32_t eax, ebx, ecx, edx;

    /* Leaf 1: ECX bit 25 = AES-NI */
    rivide_cpuid(1, &eax, &ebx, &ecx, &edx);
    if (ecx & (1u << 25)) {
        g_rivide_cpu_features |= 0x01u;
    }

    /* Leaf 7, sub-leaf 0: EBX bit 5 = AVX2 */
    rivide_cpuid(7, &eax, &ebx, &ecx, &edx);
    if (ebx & (1u << 5)) {
        g_rivide_cpu_features |= 0x04u;
    }
}

#elif defined(RIVIDE_ARCH_ARM64)

/**
 * @brief Detect ARM64 CPU features.
 *
 * On macOS Apple Silicon, uses sysctlbyname to query hardware capabilities.
 * On Linux ARM64, reads /proc/cpuinfo flags or uses compile-time detection.
 */
static void rivide_detect_arm64_features(void) {
#if defined(RIVIDE_PLATFORM_MACOS)
    int64_t val = 0;
    size_t size = sizeof(val);

    /* Query AES hardware acceleration */
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &val, &size, NULL, 0) == 0 && val) {
        g_rivide_cpu_features |= 0x02u;
    }

    /* ARM NEON is always available on Apple Silicon */
    g_rivide_cpu_features |= 0x08u;
#else
    /* Linux ARM64: use compile-time feature macros */
#if defined(__ARM_FEATURE_CRYPTO)
    g_rivide_cpu_features |= 0x02u;
#endif
#if defined(__ARM_NEON)
    g_rivide_cpu_features |= 0x08u;
#endif
#endif /* RIVIDE_PLATFORM_MACOS */
}

#endif /* architecture */

rivide_status_t rivide_init(void) {
    if (g_rivide_initialized) {
        return RIVIDE_SUCCESS;
    }

#if defined(RIVIDE_ARCH_X86_64) || defined(RIVIDE_ARCH_X86)
    rivide_detect_x86_features();
#elif defined(RIVIDE_ARCH_ARM64)
    rivide_detect_arm64_features();
#else
    (void)g_rivide_cpu_features;
#endif

    g_rivide_initialized = 1;
    return RIVIDE_SUCCESS;
}

const char *rivide_version_string(void) {
    return RIVIDE_VERSION_STRING;
}

uint32_t rivide_get_cpu_features(void) {
    return g_rivide_cpu_features;
}
