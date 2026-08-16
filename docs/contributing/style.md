<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Coding Style, License, & Documentation Standards Guide

This guide establishes the mandatory coding style, memory safety constraints, full SPDX/MIT license header requirements, and documentation standards across all C, Node.js, Rust, and Python code in **Rivide**.

## 1. Full MIT License & SPDX Header Standard

Every source, header, script, and test file across the repository MUST include a standardized SPDX and full MIT copyright notice at the top:

### C, JavaScript, TypeScript, & GYP Files (`.c`, `.h`, `.js`, `.ts`, `.gyp`)

```c
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
```

### Rust Files (`.rs`)

```rust
// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
```

### Python Files (`.py`) & Shell Scripts (`.sh`)

```python
# SPDX-License-Identifier: MIT
#
# Rivide Post-Quantum Cryptography Library
# Copyright (C) 2026 Moh. Ananda Firmansyah Putra
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
```

## 2. Memory & Zero-Allocation Constraints

1. **Zero Dynamic Allocation (0 Malloc)**:
   - **NEVER** use `malloc()`, `calloc()`, `realloc()`, or `free()`.
   - Allocate state and polynomial vectors on the execution stack or accept caller-supplied pointers.
2. **Volatile Cleansing**:
   - Always wipe sensitive secret key material before returning from function scope using `rivide_cleanse` (or language-native RAII `Drop` traits).
3. **No Prohibited Comment Banners**:
   - **NEVER** use ASCII divider lines such as `===` or `---` inside comments.
   - Use clean, minimal comment blocks.

## 3. Documentation Standards

### C99 Doxygen Standard (`.c`, `.h`)

All public and internal functions, structs, and macros MUST include formal Doxygen documentation:

```c
/**
 * @brief Encapsulate a shared secret using an ML-KEM-768 public key.
 *
 * @param[out] ct Output ciphertext buffer (1088 bytes).
 * @param[out] ss Output 32-byte shared secret key.
 * @param[in]  pk Input public key buffer (1184 bytes).
 * @return RIVIDE_SUCCESS (0) on success, or negative error code on failure.
 */
rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
```

### Rustdoc Standard (`.rs`)

All public modules, types, methods, and error variants MUST include Rustdoc comments with `# Errors` and doc-tests:

```rust
/// Encapsulates a 32-byte quantum-safe shared secret under the provided public key.
///
/// # Errors
/// Returns [`RivideError::InvalidParameter`] if the key buffer is invalid,
/// or [`RivideError::EntropyFailure`] if the CSPRNG fails.
pub fn encapsulate(public_key: &MlKem768PublicKey) -> Result<MlKem768EncapsResult, RivideError> {
    // ...
}
```

### TypeScript / JSDoc Standard (`.d.ts`, `.js`)

All exported functions and interfaces MUST include typed JSDoc descriptions:

```typescript
/**
 * Encapsulates a 32-byte quantum-safe shared secret under the provided public key.
 *
 * @param publicKey - The recipient's ML-KEM-768 public key Buffer (1184 bytes).
 * @returns An object containing the 1088-byte ciphertext and 32-byte shared secret.
 */
export function encaps(publicKey: Buffer): KemEncapsResult;
```
