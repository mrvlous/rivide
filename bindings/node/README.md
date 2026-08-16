<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide: Post-Quantum Cryptography Node.js Bindings

[![npm version](https://img.shields.io/badge/npm-v1.1.2-informational.svg)](CHANGELOG.md)
[![CI](https://github.com/mrvlous/rivide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D16.0.0-brightgreen.svg?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg?logo=typescript&logoColor=white)](index.d.ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C Standard](https://img.shields.io/badge/C-C99-green.svg)](https://github.com/mrvlous/rivide)
[![Security](https://img.shields.io/badge/Security-Constant--Time-orange.svg)](docs/api.md)
[![Memory](https://img.shields.io/badge/Memory-0%20Malloc-purple.svg)](docs/api.md)

**Rivide** for Node.js (`rivide`) provides high-performance, zero-dependency, ABI-stable **Node-API (N-API)** native bindings for the Rivide Post-Quantum Cryptography (PQC) C99 library. It implements official **NIST FIPS 203** (ML-KEM) and **NIST FIPS 204** (ML-DSA) standards with full TypeScript definitions and dual ESM/CommonJS module support.

## Key Features

- **Official NIST Post-Quantum Standards**:
    - **ML-KEM (FIPS 203)**: Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
    - **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
- **Node-API (N-API) C99 Native Engine**: ABI-stable across all Node.js versions (Node.js 16, 18, 20, 22, 24+) with zero runtime npm dependencies.
- **Hardware SIMD Vector Acceleration**: Executes native AVX2 (256-bit) and ARM NEON (128-bit) vectorized polynomial math directly in C.
- **100% TypeScript Coverage**: Complete type declarations ([`index.d.ts`](index.d.ts)) with comprehensive JSDoc hover documentation.
- **Dual Module Exports (ESM & CommonJS)**: Works out-of-the-box with `import { mlKem768 } from 'rivide'` and `const { mlKem768 } = require('rivide')`.
- **Constant-Time Side-Channel Protection**: Built-in constant-time byte comparisons (`utils.ctMemcmp`).
- **Volatile Memory Cleansing**: Explicit RAM zeroization helper (`utils.cleanse`) to prevent private key leakage.
- **Integrated Symmetric Primitives**: Native implementations of **SHA3-256/512**, **SHAKE-128/256**, and **AES-128/256-GCM** AEAD.

## Table of Contents

1. [Installation & Quick Start](#installation--quick-start)
2. [Code Tutorials & Usage Examples](#code-tutorials--usage-examples)
    - [Tutorial 1: ML-KEM-768 Quantum-Safe Key Exchange](#tutorial-1-ml-kem-768-quantum-safe-key-exchange)
    - [Tutorial 2: ML-DSA-65 Digital Signature & Verification](#tutorial-2-ml-dsa-65-digital-signature--verification)
    - [Tutorial 3: Hybrid PQC + AES-256-GCM Secure Channel](#tutorial-3-hybrid-pqc--aes-256-gcm-secure-channel)
3. [Parameter & Specification Summary](#parameter--specification-summary)
4. [Package Scripts & Automation](#package-scripts--automation)
5. [API Reference & Namespaces](#api-reference--namespaces)
6. [Documentation Map](#documentation-map)
7. [License & Maintainers](#license--maintainers)

## Installation & Quick Start

### 1. Installation

Install the package into your Node.js or TypeScript project using your preferred package manager:

```bash
# npm
npm install rivide

# pnpm
pnpm add rivide

# yarn
yarn add rivide
```

### 2. Building from Source

Clone the repository and compile using `node-gyp`:

```bash
# Clone the repository
git clone https://github.com/mrvlous/rivide.git
cd rivide/bindings/node

# Install dependencies and compile native addon
npm install
npm run build

# Run automated test suite
npm test

# Run performance benchmark suite
npm run bench
```

## Code Tutorials & Usage Examples

### Tutorial 1: ML-KEM-768 Quantum-Safe Key Exchange

This tutorial demonstrates post-quantum key encapsulation mechanism (KEM) between Alice and Bob:

```javascript
import { mlKem768, ctMemcmp, utils, constants } from 'rivide';

// 1. [Alice] Generate ML-KEM-768 keypair
console.log('[Alice] Generating ML-KEM-768 key pair...');
const alice = mlKem768.keypair();
// alice.publicKey  -> Buffer (1184 bytes)
// alice.secretKey -> Buffer (2400 bytes)

// 2. [Bob] Encapsulate a 32-byte shared secret under Alice's public key
console.log("[Bob] Encapsulating shared secret under Alice's public key...");
const bob = mlKem768.encaps(alice.publicKey);
// bob.ciphertext   -> Buffer (1088 bytes)
// bob.sharedSecret -> Buffer (32 bytes)

// 3. [Alice] Decapsulate the ciphertext using her secret key
console.log('[Alice] Decapsulating shared secret from ciphertext...');
const aliceSharedSecret = mlKem768.decaps(bob.ciphertext, alice.secretKey);

// 4. Verify that both shared secrets match in constant-time
if (ctMemcmp(aliceSharedSecret, bob.sharedSecret) === 0) {
    console.log('SUCCESS: Quantum-safe shared secret established!');
} else {
    throw new Error('Shared secret mismatch!');
}

// 5. Securely wipe sensitive private keys from RAM
utils.cleanse(alice.secretKey);
utils.cleanse(aliceSharedSecret);
utils.cleanse(bob.sharedSecret);
```

### Tutorial 2: ML-DSA-65 Digital Signature & Verification

This tutorial demonstrates signing arbitrary payloads and verifying authenticity using ML-DSA-65:

```javascript
import { mlDsa65, utils } from 'rivide';

// 1. Generate ML-DSA-65 signing keypair
console.log('[Signer] Generating ML-DSA-65 signature key pair...');
const signer = mlDsa65.keypair();
// signer.publicKey  -> Buffer (1952 bytes)
// signer.secretKey -> Buffer (4032 bytes)

// 2. Sign an arbitrary message payload
const message = Buffer.from('Post-quantum signed payload: Approve transaction $50,000 to Alice.');
console.log('[Signer] Signing message payload...');
const signature = mlDsa65.sign(message, signer.secretKey);
// signature -> Buffer (3309 bytes)

// 3. [Verifier] Verify signature authenticity against message and public key
console.log('[Verifier] Verifying digital signature...');
const isValid = mlDsa65.verify(signature, message, signer.publicKey);

if (isValid) {
    console.log('SUCCESS: Signature is VALID and AUTHENTIC!');
} else {
    throw new Error('Signature verification failed!');
}

// 4. Cleanse sensitive private key
utils.cleanse(signer.secretKey);
```

### Tutorial 3: Hybrid PQC + AES-256-GCM Secure Channel

This tutorial demonstrates end-to-end encrypted payload exchange combining ML-KEM-768 with AES-256-GCM AEAD:

```javascript
import { mlKem768, aesGcm, utils } from 'rivide';

// 1. [Server] Generate ephemeral ML-KEM-768 keypair
const server = mlKem768.keypair();

// 2. [Client] Encapsulate 256-bit symmetric session key
const kem = mlKem768.encaps(server.publicKey);
const sessionKey = kem.sharedSecret; // 32-byte quantum-safe symmetric key

// 3. [Client] Encrypt payload using AES-256-GCM AEAD
const payload = Buffer.from('Confidential financial instructions: Wire transfer confirmed.');
const iv = utils.randombytes(12);
const aad = Buffer.from('Protocol:TLS1.3-Hybrid-PQC');

const encrypted = aesGcm.encrypt256(sessionKey, iv, payload, aad);
// encrypted.ciphertext -> Buffer (same length as payload)
// encrypted.tag        -> Buffer (16 bytes)

// 4. [Server] Decapsulate symmetric key and authenticate/decrypt payload
const serverKey = mlKem768.decaps(kem.ciphertext, server.secretKey);
const decrypted = aesGcm.decrypt256(serverKey, iv, encrypted.ciphertext, encrypted.tag, aad);

console.log('Decrypted Payload:', decrypted.toString('utf8'));

// 5. Cleanse memory
utils.cleanse(server.secretKey);
utils.cleanse(sessionKey);
utils.cleanse(serverKey);
```

## Parameter & Specification Summary

| Algorithm       | Standard      | Public Key   | Secret Key   | Ciphertext / Signature | Shared Key / Security           |
| :-------------- | :------------ | :----------- | :----------- | :--------------------- | :------------------------------ |
| **ML-KEM-768**  | NIST FIPS 203 | `1184` bytes | `2400` bytes | `1088` bytes           | 32 bytes (Category 3 / AES-192) |
| **ML-KEM-1024** | NIST FIPS 203 | `1568` bytes | `3168` bytes | `1568` bytes           | 32 bytes (Category 5 / AES-256) |
| **ML-DSA-65**   | NIST FIPS 204 | `1952` bytes | `4032` bytes | `3309` bytes           | Category 3 / AES-192 equivalent |
| **ML-DSA-87**   | NIST FIPS 204 | `2592` bytes | `4896` bytes | `4627` bytes           | Category 5 / AES-256 equivalent |

## Package Scripts & Automation

The package provides automated npm scripts for development and verification:

| Command         | Action                                                                  |
| :-------------- | :---------------------------------------------------------------------- |
| `npm run build` | Compile Node-API native addon binary using `node-gyp`                   |
| `npm test`      | Run automated unit test suite using Node.js test runner (`node --test`) |
| `npm run bench` | Execute interactive Node.js performance benchmarking suite              |

## API Reference & Namespaces

### Namespaces

| Namespace   | Methods                                                                            | Description                                      |
| :---------- | :--------------------------------------------------------------------------------- | :----------------------------------------------- |
| `mlKem768`  | `keypair()`, `encaps(pk)`, `decaps(ct, sk)`                                        | NIST FIPS 203 ML-KEM-768 Key Encapsulation       |
| `mlKem1024` | `keypair()`, `encaps(pk)`, `decaps(ct, sk)`                                        | NIST FIPS 203 ML-KEM-1024 Key Encapsulation      |
| `mlDsa65`   | `keypair()`, `sign(msg, sk)`, `verify(sig, msg, pk)`                               | NIST FIPS 204 ML-DSA-65 Digital Signatures       |
| `mlDsa87`   | `keypair()`, `sign(msg, sk)`, `verify(sig, msg, pk)`                               | NIST FIPS 204 ML-DSA-87 Digital Signatures       |
| `sha3`      | `sha3_256(data)`, `sha3_512(data)`, `shake128(data, len)`, `shake256(data, len)`   | NIST FIPS 202 SHA-3 & SHAKE Extendable-Output    |
| `aesGcm`    | `encrypt128()`, `decrypt128()`, `encrypt256()`, `decrypt256()`                     | NIST SP 800-38D AES-GCM Authenticated Encryption |
| `utils`     | `cleanse(buf)`, `randombytes(len)`, `ctMemcmp(a, b)`, `getSimdCaps()`, `version()` | Security & Memory Utilities                      |

### Buffer Size Constants

```javascript
import { constants } from 'rivide';

console.log(constants.ML_KEM_768_PK_BYTES); // 1184
console.log(constants.ML_KEM_768_SK_BYTES); // 2400
console.log(constants.ML_KEM_768_CT_BYTES); // 1088
console.log(constants.ML_KEM_768_SS_BYTES); // 32
console.log(constants.ML_DSA_65_PK_BYTES); // 1952
console.log(constants.ML_DSA_65_SK_BYTES); // 4032
console.log(constants.ML_DSA_65_SIG_BYTES); // 3309
```

## Documentation Map

For detailed guides, refer to the package documentation:

- [API Reference Guide](docs/api.md)
- [Node.js Benchmarking Guide](docs/benchmarks.md)
- [TypeScript Definitions](index.d.ts)
- [Release Changelog](CHANGELOG.md)
- [Core C Library Repository](https://github.com/mrvlous/rivide)

## License & Maintainers

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

- **Author & Maintainer**: Moh. Ananda Firmansyah Putra ([@mrvlous](https://github.com/mrvlous))
- **Maintainers Roster**: [MAINTAINERS](https://github.com/mrvlous/rivide/blob/main/MAINTAINERS)
- **Contributors & Credits**: [CREDITS](https://github.com/mrvlous/rivide/blob/main/CREDITS)
