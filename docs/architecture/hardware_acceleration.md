<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Architecture: Hardware SIMD Acceleration & Vectorized NTT

This document details the Single Instruction, Multiple Data (SIMD) hardware vectorization engine and dynamic CPU feature detection architecture implemented in **Rivide**.

---

## 1. Vector Acceleration Strategies

Lattice-based cryptography algorithms spend up to 70% of execution cycles performing polynomial arithmetic and NTT butterfly loops over vectors of length $n = 256$.

Rivide provides specialized SIMD vector implementations:

| Architecture | Instruction Set | Vector Width | Coefficients Per Vector |
| :--- | :--- | :--- | :--- |
| **x86_64** | AVX2 + FMA | 256 bits (`__m256i`) | 16 $\times$ 16-bit integer coefficients |
| **x86_64** | AES-NI + PCLMULQDQ | 128 bits (`__m128i`) | Dedicated AES rounds & GHASH carryless multiplication |
| **AArch64 / ARMv8** | ARM NEON | 128 bits (`int16x8_t`) | 8 $\times$ 16-bit integer coefficients |
| **AArch64 / ARMv8** | ARM Cryptography Ext (ARM-CE) | 128 bits | Native AES and polynomial multiplication |

---

## 2. Dynamic Runtime CPU Feature Detection

Rivide queries CPU capability registers at runtime during `rivide_init()` without relying on static compiler flags alone:

```c
uint32_t rivide_get_cpu_features(void);
```

### Feature Bitmask Flags

| Flag Bit | Macro Name | Description |
| :--- | :--- | :--- |
| `1 << 0` | `RIVIDE_CPU_AESNI` | x86 Intel/AMD AES-NI instructions supported |
| `1 << 1` | `RIVIDE_CPU_ARM_CE` | ARM Cryptography Extensions supported |
| `1 << 2` | `RIVIDE_CPU_AVX2` | x86 Advanced Vector Extensions 2 (256-bit) supported |
| `1 << 3` | `RIVIDE_CPU_ARM_NEON` | ARM NEON Advanced SIMD (128-bit) supported |

If hardware acceleration features are not present (e.g. running on legacy processors or generic virtual machines), Rivide automatically and transparently falls back to optimized constant-time scalar C99 routines.
