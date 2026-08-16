<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Node.js Native Addon Subsystem Architecture

This document describes the design, directory structure, and execution model of the official **Rivide** Node.js native bindings subsystem (`bindings/node/`).

## Subsystem Organization

```
bindings/node/
├── binding.gyp          # Standard node-gyp native compilation manifest
├── package.json         # Package manifest for npm module 'rivide' v1.1.2
├── index.d.ts           # Full TypeScript type definitions and JSDoc annotations
├── README.md            # Dedicated npm package documentation & quick start
├── CHANGELOG.md         # Dedicated release changelog for npm package
├── LICENSE              # Dedicated MIT license file
├── bench.js             # Performance profiling script for Node.js runtime
├── docs/
│   ├── api.md           # Standalone TypeScript & JavaScript API reference
│   └── benchmarks.md    # Node.js performance benchmarking guide
├── lib/
│   ├── index.js         # High-level CommonJS entry point and buffer normalizers
│   └── index.mjs        # Native ECMAScript Module (ESM) export wrapper
├── src/
│   ├── napi_common.h    # Node-API macros, Buffer converters, and error throwers
│   ├── binding.c        # Main Node-API module registration & entry point
│   ├── napi_kem.c       # ML-KEM-768 and ML-KEM-1024 native handlers
│   ├── napi_dsa.c       # ML-DSA-65 and ML-DSA-87 native handlers
│   ├── napi_crypto.c    # SHA-3, SHAKE XOF, and AES-GCM AEAD native handlers
│   └── napi_utils.c     # Cleanse, randombytes, ctMemcmp, and SIMD queries
├── test/
│   ├── test_kem.js      # Automated unit tests for ML-KEM routines
│   ├── test_dsa.js      # Automated unit tests for ML-DSA signature routines
│   └── test_crypto.js   # Automated unit tests for symmetric crypto & utilities
└── examples/
    ├── kem_quickstart.js # ML-KEM-768 key encapsulation demonstration
    ├── dsa_signature.js  # ML-DSA-65 digital signature demonstration
    └── hybrid_aead.js    # Hybrid PQC + AES-256-GCM authenticated channel
```

## Technical Architecture

1. **Node-API (N-API) C99 Foundation**:
   - Implemented in pure C99 (`node_api.h`) with zero external runtime npm dependencies.
   - Provides ABI stability across all active LTS and current Node.js versions (v16, v18, v20, v22, v24+).
2. **Zero-Copy Buffer Interface**:
   - Directly maps JavaScript `Buffer` and `Uint8Array` allocations to fixed-size stack buffers in the underlying C99 library.
3. **Memory Safety & Zeroization**:
   - Exposes `utils.cleanse(buffer)` to guarantee explicit volatile zeroization of sensitive private keys in Node.js applications.
4. **Dual ESM & CommonJS Support**:
   - Seamlessly imported via `import { mlKem768 } from 'rivide'` or `const { mlKem768 } = require('rivide')`.
5. **Universal Package Manager Compatibility**:
   - Fully compatible with `npm`, `pnpm`, and `yarn` installation workflows with automated source packaging.

## Build and Test Automation

```bash
# Build native addon using node-gyp
make node-build

# Run automated Node.js test suite
make node-test

# Run Node.js runtime performance benchmarks
make node-bench
```
