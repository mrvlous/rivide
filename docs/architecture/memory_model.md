<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Architecture: Zero-Allocation Memory Model & Safety

This document describes the memory allocation model, stack isolation, and memory zeroization guarantees enforced across **Rivide**.

## 1. The Zero-Malloc Guarantee (0 Malloc)

In high-assurance cryptographic implementations, dynamic heap allocation (`malloc`, `calloc`, `realloc`, `free`) introduces several severe security and operational risks:
1. **Memory Fragmentation & Allocation Failures**: In long-running services or constrained embedded kernels, heap exhaustion can cause unpredictable runtime crashes.
2. **Heap Residual Leakage**: Freeing heap buffers does not guarantee physical RAM erasure; sensitive private key remnants can linger across subsequent heap allocations.
3. **Allocator Lock Contention**: Multi-threaded servers suffer latency spikes when multiple threads compete for heap allocator locks during high-throughput cryptographic operations.

### Rivide's Solution: Pure Stack & Deterministic Memory

Rivide prohibits all dynamic memory allocation functions in its C core engine:
- All cryptographic key generation, signing, verification, encapsulation, and hashing operations compute within fixed-size stack frames.
- Key and ciphertext structures are passed via pointer to caller-allocated memory.
- Peak stack usage per algorithm is strictly bounded and deterministic.

## 2. Volatile Memory Cleansing (`rivide_cleanse`)

Standard memory zeroing routines like `memset(ptr, 0, len)` can be optimized away by modern C optimizing compilers (GCC, Clang, MSVC) under **Dead-Store Elimination (DSE)** if the buffer is not accessed again before being deallocated or returning from the function frame.

### Volatile Assembly Barrier

Rivide implements a multi-layer secure zeroization primitive:

```c
void rivide_cleanse(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }

    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }

    /* Compiler memory clobber barrier */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
```

The `volatile` pointer access combined with the `__asm__ __volatile__` clobber barrier ensures that the compiler treats the memory region as externally observable, preventing DSE under any compiler optimization level (`-O2`, `-O3`, `-Ofast`, `-flto`).

## 3. RAII Memory Safety in High-Level Bindings

In high-level language bindings, manual zeroization is automated using language-native lifecycle mechanisms:
- **Rust (`bindings/rust/`)**: All secret key types implement the `Drop` trait and automatically trigger `rivide_cleanse` when leaving scope.
- **Node.js (`bindings/node/`)**: Exposes `utils.cleanse(buffer)` for explicit RAM zeroing before Node.js V8 garbage collector passes.
