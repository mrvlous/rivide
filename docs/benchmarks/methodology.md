<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Benchmarks: Methodology & Performance Measurement

This document details the benchmarking framework, warmup protocol, timing precision, and statistical methods used across **Rivide**.

---

## 1. High-Precision Timing Sources

- **C Native**: Uses POSIX `clock_gettime(CLOCK_MONOTONIC, &ts)` or platform cycle counters (`rdtsc`) with nanosecond resolution.
- **Node.js**: Uses `process.hrtime.bigint()` nanosecond timers.
- **Rust**: Uses `std::time::Instant` high-precision platform monotonic clocks.

---

## 2. Benchmark Protocol

1. **Warmup Phase**: Executes 50 iterations prior to timing to populate CPU L1/L2 instruction and data caches, prime branch predictors, and stabilize CPU frequency scaling.
2. **Timing Loop**: Executes 1,000 measured iterations for each cryptographic primitive.
3. **Statistical Metrics**:
   - **Throughput**: Calculated as $\text{Operations Per Second} = \frac{N}{\Delta t_{\text{seconds}}}$.
   - **Latency**: Calculated as $\mu\text{s / Operation} = \frac{\Delta t_{\text{seconds}}}{N} \times 10^6$.
