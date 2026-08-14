# Dedicated Benchmark Subsystem Architecture

This document describes the dedicated benchmarking subsystem in **Rivide** (`benchmarks/`), designed for performance profiling and throughput measurement.

## Subsystem Organization

```
benchmarks/
├── bench_harness.h   # Monotonic timer, CPU feature detection, and compiler metadata reporting
├── bench_main.c      # Main executable entry point with configurable iterations
├── bench_kem.c       # KeyGen, Encaps, and Decaps for ML-KEM-768 and ML-KEM-1024
├── bench_dsa.c       # KeyGen, Sign, and Verify for ML-DSA-65 and ML-DSA-87
└── bench_crypto.c    # Throughput benchmarks (MB/sec) for SHA-3, SHAKE, and AES-256-GCM
```

## Hardware and Environment Reporting

When executed, the benchmark harness automatically identifies:
- **Compiler Identification**: GCC, Clang, or MSVC version.
- **Build Optimization**: Release (`-O3 / -DNDEBUG`) vs Debug.
- **Hardware Acceleration Bitmask**:
  - `0x01`: AES-NI Instruction Set
  - `0x02`: ARMv8 Cryptography Extensions
  - `0x04`: AVX2 256-bit SIMD Vectorization
  - `0x08`: ARM NEON 128-bit SIMD Vectorization

## Execution and Configuration

```bash
# Run default benchmark suite (100 iterations per operation)
make bench

# Run with custom iteration count via environment variable
BENCH_ITERS=500 make bench

# Run directly with CLI parameter
./build/rivide_bench 1000
```
