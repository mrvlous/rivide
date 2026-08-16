<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# C API Reference: Low-Level NTT & Hardware SIMD Detection

Public C99 declarations for CPU feature querying and SIMD polynomial vector routines.

Header: `<rivide/rivide.h>`

## 1. Runtime CPU Feature Query

```c
uint32_t rivide_get_cpu_features(void);
```

Returns a bitmask of detected CPU SIMD hardware acceleration capabilities.

### Bitmask Constants

```c
#define RIVIDE_CPU_AESNI    (1U << 0)
#define RIVIDE_CPU_ARM_CE   (1U << 1)
#define RIVIDE_CPU_AVX2     (1U << 2)
#define RIVIDE_CPU_ARM_NEON (1U << 3)
```
