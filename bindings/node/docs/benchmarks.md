<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Node.js Performance Benchmarking Guide

This document describes the benchmarking methodology and throughput metrics for **`rivide`** on the Node.js runtime.

## Running the Benchmark Suite

The benchmark script [`bench.js`](../bench.js) measures operation throughput (ops/sec) and latency (us/op) across all cryptographic routines:

```bash
# Run benchmark via npm
npm run bench

# Or directly with node
node bench.js
```

## Hardware Acceleration

Rivide leverages hardware acceleration directly from C99 via Node-API:

- **AVX2 256-bit SIMD Vectorization**: Accelerates Number Theoretic Transform (NTT) polynomial multiplications.
- **AES-NI**: Hardware-accelerated AES round instructions.
- **ARM NEON**: 128-bit vector execution on Apple Silicon and ARM64 servers.

## Representative Performance Profile

| Algorithm       | Operation    | Node.js Throughput (ops/sec) | Latency (us/op) |
| :-------------- | :----------- | :--------------------------- | :-------------- |
| **ML-KEM-768**  | KeyGen       | ~8,690 ops/sec               | ~115 us         |
| **ML-KEM-768**  | Encaps       | ~6,400 ops/sec               | ~156 us         |
| **ML-KEM-768**  | Decaps       | ~6,520 ops/sec               | ~153 us         |
| **ML-KEM-1024** | KeyGen       | ~5,560 ops/sec               | ~180 us         |
| **ML-KEM-1024** | Encaps       | ~5,080 ops/sec               | ~196 us         |
| **ML-KEM-1024** | Decaps       | ~4,720 ops/sec               | ~211 us         |
| **ML-DSA-65**   | KeyGen       | ~2,810 ops/sec               | ~355 us         |
| **ML-DSA-65**   | Sign         | ~1,140 ops/sec               | ~876 us         |
| **ML-DSA-65**   | Verify       | ~2,690 ops/sec               | ~370 us         |
| **ML-DSA-87**   | KeyGen       | ~1,940 ops/sec               | ~515 us         |
| **ML-DSA-87**   | Sign         | ~515 ops/sec                 | ~1,939 us       |
| **ML-DSA-87**   | Verify       | ~1,720 ops/sec               | ~578 us         |
| **SHA3-256**    | 4 KB Hash    | ~29,790 ops/sec              | ~33 us          |
| **AES-256-GCM** | 4 KB Encrypt | ~1,520 ops/sec               | ~655 us         |
