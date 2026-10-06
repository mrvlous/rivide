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
    constants,
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

- `cleanse(buffer: Buffer | Uint8Array): void`
- `randombytes(length: number): Buffer`
- `ctMemcmp(a: Buffer | Uint8Array, b: Buffer | Uint8Array): number`
- `getSimdCaps(): { hasAesni: boolean, hasArmCrypto: boolean, hasAvx2: boolean, hasNeon: boolean, bitmask: number }`
- `version(): string`

## 6. Buffer Size Constants (`constants`)

- `ML_KEM_768_PK_BYTES` (1184), `ML_KEM_768_SK_BYTES` (2400), `ML_KEM_768_CT_BYTES` (1088), `ML_KEM_768_SS_BYTES` (32)
- `ML_KEM_1024_PK_BYTES` (1568), `ML_KEM_1024_SK_BYTES` (3168), `ML_KEM_1024_CT_BYTES` (1568), `ML_KEM_1024_SS_BYTES` (32)
- `ML_DSA_65_PK_BYTES` (1952), `ML_DSA_65_SK_BYTES` (4032), `ML_DSA_65_SIG_BYTES` (3309)
- `ML_DSA_87_PK_BYTES` (2592), `ML_DSA_87_SK_BYTES` (4896), `ML_DSA_87_SIG_BYTES` (4627)
- `SHA3_256_BYTES` (32), `SHA3_512_BYTES` (64), `AES_GCM_IV_BYTES` (12), `AES_GCM_TAG_BYTES` (16)
