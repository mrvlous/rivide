<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Node.js API Reference: `rivide` Package

Complete API documentation for the official **`rivide`** Node.js native Node-API bindings.

## 1. Module Import

```typescript
import {
    mlKem768,
    mlKem1024,
    mlDsa65,
    mlDsa87,
    sha3,
    aesGcm,
    utils,
} from 'rivide';
```

## 2. Key Encapsulation (`mlKem768`, `mlKem1024`)

- `keypair(): { publicKey: Buffer, secretKey: Buffer }`
- `encaps(publicKey: Buffer): { ciphertext: Buffer, sharedSecret: Buffer }`
- `decaps(ciphertext: Buffer, secretKey: Buffer): Buffer`

## 3. Digital Signatures (`mlDsa65`, `mlDsa87`)

- `keypair(): { publicKey: Buffer, secretKey: Buffer }`
- `sign(message: Buffer | Uint8Array, secretKey: Buffer): Buffer`
- `verify(signature: Buffer | Uint8Array, message: Buffer | Uint8Array, publicKey: Buffer): boolean`

## 4. Symmetric Cryptography

### SHA-3 & SHAKE (`sha3`)
- `sha3_256(data: Buffer | Uint8Array): Buffer`
- `sha3_512(data: Buffer | Uint8Array): Buffer`
- `shake128(data: Buffer | Uint8Array, outputLength: number): Buffer`
- `shake256(data: Buffer | Uint8Array, outputLength: number): Buffer`

### AES-GCM AEAD (`aesGcm`)
- `encrypt128(key: Buffer, iv: Buffer, plaintext: Buffer, aad?: Buffer): { ciphertext: Buffer, tag: Buffer }`
- `decrypt128(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad?: Buffer): Buffer`
- `encrypt256(key: Buffer, iv: Buffer, plaintext: Buffer, aad?: Buffer): { ciphertext: Buffer, tag: Buffer }`
- `decrypt256(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad?: Buffer): Buffer`

## 5. Utilities (`utils`)

- `cleanse(buffer: Buffer): void`
- `randombytes(length: number): Buffer`
- `ctMemcmp(a: Buffer, b: Buffer): number`
- `getSimdCaps(): { hasAesni: boolean, hasArmCe: boolean, hasAvx2: boolean, hasNeon: boolean }`
- `version(): string`
