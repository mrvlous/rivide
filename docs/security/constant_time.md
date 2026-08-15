<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security: Constant-Time Engineering & Side-Channel Mitigation

This document details the constant-time coding disciplines, arithmetic techniques, and timing side-channel countermeasures implemented in **Rivide**.

---

## 1. Principles of Constant-Time Implementation

To prevent timing side-channel attacks, execution time and instruction traces must remain strictly independent of all sensitive secret data (e.g. secret keys, error polynomials, random coins).

Rivide enforces three mandatory constant-time rules for secret-dependent paths:

1. **No Secret-Dependent Branching**: Prohibits `if`, `else`, `switch`, `? :`, and loop conditions that evaluate secret values.
2. **No Secret-Indexed Memory Lookups**: Prohibits array access using secret indices ($A[secret]$) to prevent cache-line timing attacks.
3. **No Variable-Time CPU Instructions**: Avoids integer division (`/`), remainder (`%`), and variable-latency barrel rotations on architectures where timing depends on operand magnitude.

---

## 2. Constant-Time Primitives in Rivide

### Constant-Time Memory Comparison (`rivide_ct_memcmp`)

Standard `memcmp` returns early upon finding the first differing byte, leaking the position of mismatches:

```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (pa[i] ^ pb[i]);
    }

    return (int)diff;
}
```

This ensures that comparison latency is identical regardless of where mismatches occur.

### Constant-Time Multiplexer (`rivide_ct_select`)

Selects between two byte buffers based on a mask without conditional branching:

```c
void rivide_ct_select(uint8_t *dest, const uint8_t *a, const uint8_t *b, size_t len, uint8_t mask) {
    for (size_t i = 0; i < len; i++) {
        dest[i] = b[i] ^ (mask & (a[i] ^ b[i]));
    }
}
```
