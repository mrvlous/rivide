<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security: Memory Safety Guarantees & Cleansing

This document details the volatile memory barriers, stack lifecycle management, and spatial safety guarantees implemented across **Rivide**.

---

## 1. Spatial Memory Safety Guarantees

Lattice cryptography parameters feature exact fixed-size byte buffers (e.g. `1184` bytes for ML-KEM-768 public keys, `3309` bytes for ML-DSA-65 signatures).

Rivide enforces spatial memory safety through:
1. **Explicit Length Constants**: Every API consumes fixed-size buffers defined as standardized macros in `rivide_types.h`.
2. **Bounds-Checked Slicing**: Rejection sampling loops check bounds before accessing output buffers.
3. **No Hidden State Re-allocation**: Zero dynamic pointer reallocation ensures memory ranges never grow or shrink dynamically at runtime.

---

## 2. Volatile Cleansing & Memory Zeroization

When functions complete execution, secret keys and intermediate entropy must not remain in CPU registers or RAM:

```c
/* Wipe secret key state immediately after use */
rivide_cleanse(sk, sizeof(sk));
```

### Protection Against Compiler Optimization

Using volatile memory writes coupled with assembly memory barriers:
- Prevents dead-store elimination across all GCC, Clang, and MSVC optimization levels.
- Forces physical write-back to RAM before returning from cryptographic routine boundaries.

---

## 3. High-Level RAII Drop Integration

In Rust, memory safety is enforced at the type system level:
- Secrets cannot be cloned or moved inadvertently without explicit operations.
- Structures implementing `Drop` invoke `rivide_cleanse` automatically upon leaving local function scope.
