<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security: Memory Safety Guarantees & Cleansing

This document details the volatile memory barriers, stack lifecycle management, and spatial safety guarantees implemented across **Rivide**.

## 1. Spatial Memory Safety Guarantees

Lattice cryptography parameters feature exact fixed-size byte buffers (e.g. `1184` bytes for ML-KEM-768 public keys, `3309` bytes for ML-DSA-65 signatures).

Rivide enforces spatial memory safety through:
1. **Explicit Length Constants**: Every API consumes fixed-size buffers defined as standardized macros in `rivide_types.h`.
2. **Bounds-Checked Slicing**: Rejection sampling loops check bounds before accessing output buffers.
3. **No Hidden State Re-allocation**: Zero dynamic pointer reallocation ensures memory ranges never grow or shrink dynamically at runtime.

## 2. Volatile Cleansing & Memory Zeroization

When functions complete execution, secret keys, intermediate polynomials, and ephemeral entropy must not remain in CPU registers or RAM:

```c
/* Wipe secret key state immediately after use */
rivide_cleanse(sk, sizeof(sk));
```

### Protection Against Compiler Optimization

Using volatile memory writes coupled with assembly memory barriers:
- Prevents dead-store elimination (DSE) across all GCC, Clang, and MSVC optimization levels (`-O2`, `-O3`, `-Ofast`, `-flto`).
- Forces physical write-back to RAM before returning from cryptographic routine boundaries.

### Comprehensive Stack Scrubbing Invariants

Rivide systematically sanitizes all sensitive stack buffers across all primitives:
1. **ML-DSA Ephemeral States**: Cleanses all masking and secret vectors ($\mathbf{s}_1, \mathbf{s}_2, \mathbf{t}_0, \mathbf{t}_1, \mathbf{w}, \mathbf{w}_0, \mathbf{w}_1, \mathbf{y}, \mathbf{z}, \mathbf{cs}_2, \mathbf{ct}_0$) in key generation and signing before returning to the caller.
2. **ML-KEM Ephemeral States**: Cleanses seeds ($\rho, \sigma$), matrix rows ($\mathbf{a}_{row}$), and polynomial vectors ($\mathbf{s}, \mathbf{e}, \mathbf{t}$) in key generation, as well as ephemeral secret buffers on both success and RNG failure paths in encapsulation.
3. **GHASH Stack Cleansing**: Cleanses intermediate hash keys ($H$), multiplication accumulators, and input block chunks in `rivide_ghash_mult` and `rivide_ghash_update`.
4. **Defensive Digest Cleansing**: Zeroizes output digest buffers on invalid NULL input pointers in SHA-3 and SHAKE routines to prevent silent forged empty-digest outputs.

## 3. High-Level RAII Drop Integration

In Rust, memory safety is enforced at the type system level:
- Secrets cannot be cloned or moved inadvertently without explicit operations.
- Structures implementing `Drop` invoke `rivide_cleanse` automatically upon leaving local function scope.
