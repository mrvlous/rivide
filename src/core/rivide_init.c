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

/** @brief Tracks whether rivide_init() has already been called. */
static volatile int g_rivide_initialized = 0;

/**
 * @brief Runtime CPU feature flags, populated by rivide_init().
 *
 * These flags are set once at initialization and read thereafter.
 * Bit 0: AES-NI available
 * Bit 1: ARM Crypto Extensions available
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
 */
static void rivide_detect_x86_features(void) {
    uint32_t eax, ebx, ecx, edx;
    rivide_cpuid(1, &eax, &ebx, &ecx, &edx);

    /* ECX bit 25: AES-NI support */
    if (ecx & (1u << 25)) {
        g_rivide_cpu_features |= 0x01u;
    }
}

#endif /* x86 */

rivide_status_t rivide_init(void) {
    if (g_rivide_initialized) {
        return RIVIDE_SUCCESS;
    }

#if defined(RIVIDE_ARCH_X86_64) || defined(RIVIDE_ARCH_X86)
    rivide_detect_x86_features();
#else
    (void)g_rivide_cpu_features;
#endif

    g_rivide_initialized = 1;
    return RIVIDE_SUCCESS;
}

const char *rivide_version_string(void) {
    return RIVIDE_VERSION_STRING;
}
