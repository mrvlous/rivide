<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Integration Guide: Embedded Systems & Firmware Security

This guide describes best practices for deploying Rivide into resource-constrained microcontrollers and bare-metal IoT firmware environments.

## Embedded Constraints & Features

1. **Zero Dynamic Allocation (0 Malloc)**:
   - Rivide does not invoke `malloc()` or `free()`. Memory footprint is completely deterministic and bounded at compile time.
2. **Standard Stack Allocation**:
   - For microcontrollers with limited RAM (e.g. ARM Cortex-M4/M7 with $\le 64$ KB RAM), buffer sizes for ML-KEM-768 key pairs (1184 bytes public key, 2400 bytes secret key) fit comfortably within function stack frames or static global arrays.
3. **Custom Entropy Hook**:
   - For bare-metal platforms without POSIX OS support, register an RNG callback via `rivide_set_rng_callback()` to sample hardware True Random Number Generators (TRNG).

```c
#include "rivide/rivide.h"
#include "rivide/utils/random.h"

/* Custom hardware TRNG callback for bare-metal ARM Cortex-M */
static rivide_status_t trng_callback(uint8_t *out, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        /* Sample from hardware TRNG register */
        while (!(TRNG->SR & TRNG_SR_DATRDY));
        out[i] = (uint8_t)TRNG->DR;
    }
    return RIVIDE_SUCCESS;
}

void init_embedded_entropy(void) {
    /* Register custom TRNG hook atomically */
    rivide_set_rng_callback(trng_callback);
}
```
