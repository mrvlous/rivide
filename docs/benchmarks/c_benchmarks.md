<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Benchmarks: C Native Benchmark Subsystem

Instructions and execution guide for the C native benchmark binary (`rivide_bench`).

## 1. Execution

From the repository root:

```bash
make bench
```

Or via direct binary execution:

```bash
./build/rivide_bench
```

## 2. Benchmark Output Sample

```text
Rivide Post-Quantum Cryptography Benchmark Suite v1.1.4

Environment Information:
  Compiler             : GCC 16.2.1
  Build Configuration  : Release (-O3 / -DNDEBUG)
  Benchmark Iterations : 100 runs per operation

Detected Hardware Acceleration Capabilities:
  AES-NI Acceleration  : YES
  ARM Crypto Ext       : NO
  AVX2 SIMD Vector     : YES
  ARM NEON SIMD        : NO

[Benchmark] ML-KEM-768
  KeyGen  :   8815.55 ops/sec ( 113.44 us/op)
  Encaps  :   7941.99 ops/sec ( 125.91 us/op)
  Decaps  :   6493.72 ops/sec ( 154.00 us/op)

[Benchmark] ML-DSA-65
  KeyGen  :   2841.09 ops/sec ( 351.98 us/op)
  Sign    :    400.60 ops/sec (2496.23 us/op)
  Verify  :   3013.90 ops/sec ( 331.80 us/op)
```
