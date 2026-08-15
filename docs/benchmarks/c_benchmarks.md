<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Benchmarks: C Native Benchmark Subsystem

Instructions and execution guide for the C native benchmark binary (`rivide_bench`).

---

## 1. Execution

From the repository root:

```bash
make bench
```

Or via direct binary execution:

```bash
./build/rivide_bench
```

---

## 2. Benchmark Output Sample

```text
================================================================================
  Rivide Post-Quantum Cryptography Benchmark Suite
  Library Version : 1.1.0
  Modulus Info    : q = 3329 (ML-KEM), q = 8380417 (ML-DSA)
  CPU Features    : AVX2: YES, AES-NI: YES, NEON: NO
================================================================================

[Benchmark] ML-KEM-768
  KeyGen  :   7240.12 ops/sec ( 138.12 us/op)
  Encaps  :   5820.45 ops/sec ( 171.81 us/op)
  Decaps  :   5120.30 ops/sec ( 195.30 us/op)

[Benchmark] ML-DSA-65
  KeyGen  :   3420.10 ops/sec ( 292.39 us/op)
  Sign    :    890.40 ops/sec (1123.09 us/op)
  Verify  :   3150.20 ops/sec ( 317.44 us/op)
```
