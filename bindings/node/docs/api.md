<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide Node.js API Reference

Complete API documentation for the **`rivide`** Node.js native package.

## Installation

Install via your preferred package manager:

```bash
# npm
npm install rivide

# pnpm
pnpm add rivide

# yarn
yarn add rivide
```

## Module Structure

The package exports both namespace modules and direct utility helpers:

```javascript
import { mlKem768, mlKem1024, mlDsa65, mlDsa87, sha3, aesGcm, utils, constants } from 'rivide';
```

## Buffer Size Constants (`constants`)

| Constant               | Value (Bytes) | Description                   |
| :--------------------- | :------------ | :---------------------------- |
| `ML_KEM_768_PK_BYTES`  | `1184`        | ML-KEM-768 Public Key         |
| `ML_KEM_768_SK_BYTES`  | `2400`        | ML-KEM-768 Secret Key         |
| `ML_KEM_768_CT_BYTES`  | `1088`        | ML-KEM-768 Ciphertext         |
| `ML_KEM_768_SS_BYTES`  | `32`          | ML-KEM Shared Secret          |
| `ML_KEM_1024_PK_BYTES` | `1568`        | ML-KEM-1024 Public Key        |
| `ML_KEM_1024_SK_BYTES` | `3168`        | ML-KEM-1024 Secret Key        |
| `ML_KEM_1024_CT_BYTES` | `1568`        | ML-KEM-1024 Ciphertext        |
| `ML_KEM_1024_SS_BYTES` | `32`          | ML-KEM Shared Secret          |
| `ML_DSA_65_PK_BYTES`   | `1952`        | ML-DSA-65 Public Key          |
| `ML_DSA_65_SK_BYTES`   | `4032`        | ML-DSA-65 Secret Key          |
| `ML_DSA_65_SIG_BYTES`  | `3309`        | ML-DSA-65 Signature           |
| `ML_DSA_87_PK_BYTES`   | `2592`        | ML-DSA-87 Public Key          |
| `ML_DSA_87_SK_BYTES`   | `4896`        | ML-DSA-87 Secret Key          |
| `ML_DSA_87_SIG_BYTES`  | `4627`        | ML-DSA-87 Signature           |
| `SHA3_256_BYTES`       | `32`          | SHA3-256 Digest Output        |
| `SHA3_512_BYTES`       | `64`          | SHA3-512 Digest Output        |
| `AES_GCM_IV_BYTES`     | `12`          | AES-GCM Initialization Vector |
| `AES_GCM_TAG_BYTES`    | `16`          | AES-GCM Authentication Tag    |

## ML-KEM-768 (`mlKem768`)

### `mlKem768.keypair(): { publicKey: Buffer, secretKey: Buffer }`

Generates a new post-quantum ML-KEM-768 keypair.

### `mlKem768.encaps(publicKey: Buffer | Uint8Array): { ciphertext: Buffer, sharedSecret: Buffer }`

Encapsulates a 32-byte shared secret under an 1184-byte public key.

### `mlKem768.decaps(ciphertext: Buffer | Uint8Array, secretKey: Buffer | Uint8Array): Buffer`

Decapsulates a 32-byte shared secret from a 1088-byte ciphertext using a 2400-byte secret key with constant-time implicit rejection.

## ML-KEM-1024 (`mlKem1024`)

### `mlKem1024.keypair(): { publicKey: Buffer, secretKey: Buffer }`

Generates a new post-quantum ML-KEM-1024 keypair (NIST Security Category 5).

### `mlKem1024.encaps(publicKey: Buffer | Uint8Array): { ciphertext: Buffer, sharedSecret: Buffer }`

Encapsulates a 32-byte shared secret under a 1568-byte public key.

### `mlKem1024.decaps(ciphertext: Buffer | Uint8Array, secretKey: Buffer | Uint8Array): Buffer`

Decapsulates a 32-byte shared secret from a 1568-byte ciphertext using a 3168-byte secret key.

## ML-DSA-65 (`mlDsa65`)

### `mlDsa65.keypair(): { publicKey: Buffer, secretKey: Buffer }`

Generates a new post-quantum ML-DSA-65 signing keypair.

### `mlDsa65.sign(message: Buffer | Uint8Array | string, secretKey: Buffer | Uint8Array): Buffer`

Signs an arbitrary message payload using a 4032-byte secret key, returning a 3309-byte signature.

### `mlDsa65.verify(signature: Buffer | Uint8Array, message: Buffer | Uint8Array | string, publicKey: Buffer | Uint8Array): boolean`

Verifies signature validity against message and public key. Returns `true` if valid, `false` otherwise.

## ML-DSA-87 (`mlDsa87`)

### `mlDsa87.keypair(): { publicKey: Buffer, secretKey: Buffer }`

Generates a new post-quantum ML-DSA-87 signing keypair (NIST Security Category 5).

### `mlDsa87.sign(message: Buffer | Uint8Array | string, secretKey: Buffer | Uint8Array): Buffer`

Signs an arbitrary message payload using a 4896-byte secret key, returning a 4627-byte signature.

### `mlDsa87.verify(signature: Buffer | Uint8Array, message: Buffer | Uint8Array | string, publicKey: Buffer | Uint8Array): boolean`

Verifies signature validity against message and public key. Returns `true` if valid, `false` otherwise.

## SHA-3 & SHAKE (`sha3`)

### `sha3.sha3_256(data: Buffer | Uint8Array | string): Buffer`

Computes 256-bit SHA-3 digest (32 bytes).

### `sha3.sha3_512(data: Buffer | Uint8Array | string): Buffer`

Computes 512-bit SHA-3 digest (64 bytes).

### `sha3.shake128(data: Buffer | Uint8Array | string, outputLength: number): Buffer`

Computes SHAKE-128 extendable-output hash of arbitrary length.

### `sha3.shake256(data: Buffer | Uint8Array | string, outputLength: number): Buffer`

Computes SHAKE-256 extendable-output hash of arbitrary length.

## AES-GCM AEAD (`aesGcm`)

### `aesGcm.encrypt128(key, iv, plaintext, aad?): { ciphertext: Buffer, tag: Buffer }`

Encrypts plaintext using AES-128-GCM with a 16-byte key and 12-byte IV.

### `aesGcm.decrypt128(key, iv, ciphertext, tag, aad?): Buffer`

Authenticates and decrypts ciphertext using AES-128-GCM.

### `aesGcm.encrypt256(key, iv, plaintext, aad?): { ciphertext: Buffer, tag: Buffer }`

Encrypts plaintext using AES-256-GCM with a 32-byte key and 12-byte IV.

### `aesGcm.decrypt256(key, iv, ciphertext, tag, aad?): Buffer`

Authenticates and decrypts ciphertext using AES-256-GCM.

## Utilities (`utils`)

### `utils.cleanse(buffer: Buffer | Uint8Array): void`

Securely zeroes out sensitive memory in RAM using volatile barriers.

### `utils.randombytes(length: number): Buffer`

Queries the operating system CSPRNG (`getrandom`, `getentropy`, `BCryptGenRandom`) for high-entropy random bytes.

### `utils.ctMemcmp(a: Buffer | Uint8Array, b: Buffer | Uint8Array): number`

Constant-time byte comparison. Returns `0` if buffers are identical, non-zero if different.

### `utils.getSimdCaps(): SimdCapabilities`

Returns runtime CPU SIMD capability flags (`hasAvx2`, `hasAesni`, `hasNeon`, `hasArmCrypto`, `bitmask`).

### `utils.version(): string`

Returns library version string (e.g. `"1.1.0"`).
