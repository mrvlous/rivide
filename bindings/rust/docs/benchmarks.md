<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide Rust Performance Benchmark Guide

This document provides instructions for executing, configuring, and analyzing performance benchmarks for the **`rivide`** Rust crate.

## Overview

The Rust benchmark harness measures operations per second (`ops/sec`) and execution latency in microseconds per operation (`us/op`) for all core primitives:
- **ML-KEM-768 & ML-KEM-1024** (KeyGen, Encaps, Decaps)
- **ML-DSA-65 & ML-DSA-87** (KeyGen, Sign, Verify)
- **SHA3-256, SHAKE-256, & AES-256-GCM AEAD** (over 4 KB payload buffers)

## Executing Benchmarks

### Option 1: Via Cargo Bench

```bash
cd bindings/rust
cargo bench
```

### Option 2: Via Master Makefile Target

From the repository root:

```bash
make rust-bench
```

### Option 3: Via Standalone Example Binary

```bash
cargo run --release --example bench
```

## Benchmark Output Format

```text
Rivide Rust Post-Quantum Cryptography Benchmark Suite v1.1.0

Hardware Acceleration : AVX2: YES, AES-NI: YES, NEON: NO, ARM-CE: NO

NIST FIPS 203 ML-KEM Benchmarks:
  ML-KEM-768 KeyGen            :   6287.79 ops/sec ( 159.04 us/op)
  ML-KEM-768 Encaps            :   5205.31 ops/sec ( 192.11 us/op)
  ML-KEM-768 Decaps            :   4327.97 ops/sec ( 231.06 us/op)

  ML-KEM-1024 KeyGen           :   3778.10 ops/sec ( 264.68 us/op)
  ML-KEM-1024 Encaps           :   3422.67 ops/sec ( 292.17 us/op)
  ML-KEM-1024 Decaps           :   3393.65 ops/sec ( 294.67 us/op)

NIST FIPS 204 ML-DSA Benchmarks:
  ML-DSA-65 KeyGen             :   2779.40 ops/sec ( 359.79 us/op)
  ML-DSA-65 Sign               :    964.67 ops/sec (1036.63 us/op)
  ML-DSA-65 Verify             :   3105.68 ops/sec ( 321.99 us/op)

  ML-DSA-87 KeyGen             :   1834.95 ops/sec ( 544.97 us/op)
  ML-DSA-87 Sign               :   1394.77 ops/sec ( 716.96 us/op)
  ML-DSA-87 Verify             :   1821.86 ops/sec ( 548.89 us/op)

Symmetric Primitives Benchmarks:
  SHA3-256 (4 KB)              :  28255.33 ops/sec (  35.39 us/op)
  SHAKE-256 (4 KB -> 32B)      :  36607.67 ops/sec (  27.32 us/op)
  AES-256-GCM Encrypt (4 KB)   :   1672.30 ops/sec ( 597.98 us/op)
  AES-256-GCM Decrypt (4 KB)   :   1570.72 ops/sec ( 636.65 us/op)

[SUCCESS] Rust Benchmark Suite Execution Complete.
```

## Performance Optimizations

1. **Native C99 Engine**: Compiled with `-std=c99 -O3` optimization flags.
2. **SIMD Vectorization**: Automated CPU capability detection utilizing AVX2 (256-bit) and ARM NEON (128-bit) vectorized polynomial math.
3. **Zero Heap Allocations**: 100% stack-allocated byte arrays preventing allocator lock contention.
