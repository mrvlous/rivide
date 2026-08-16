<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rust API Reference: `rivide` Crate

Complete API documentation for the official **`rivide`** Rust crate.

## 1. Module Structure

```rust
use rivide::{
    kem::{MlKem768, MlKem1024, MlKem768KeyPair, MlKem1024KeyPair},
    dsa::{MlDsa65, MlDsa87, MlDsa65KeyPair, MlDsa87KeyPair, MlDsa65Signature, MlDsa87Signature},
    crypto::{Sha3, AesGcm, AesGcmResult},
    utils::{cleanse, ct_memcmp, get_cpu_features, randombytes, randombytes_into, version, CpuFeatures},
    error::RivideError,
};
```

## 2. Key Encapsulation (`rivide::kem`)

- `MlKem768::keypair() -> Result<MlKem768KeyPair, RivideError>`
- `MlKem768::encapsulate(public_key: &MlKem768PublicKey) -> Result<MlKem768EncapsResult, RivideError>`
- `MlKem768::decapsulate(ciphertext: &[u8; 1088], secret_key: &MlKem768SecretKey) -> Result<[u8; 32], RivideError>`
- `MlKem1024::keypair() -> Result<MlKem1024KeyPair, RivideError>`
- `MlKem1024::encapsulate(public_key: &MlKem1024PublicKey) -> Result<MlKem1024EncapsResult, RivideError>`
- `MlKem1024::decapsulate(ciphertext: &[u8; 1568], secret_key: &MlKem1024SecretKey) -> Result<[u8; 32], RivideError>`

## 3. Digital Signatures (`rivide::dsa`)

- `MlDsa65::keypair() -> Result<MlDsa65KeyPair, RivideError>`
- `MlDsa65::sign(message: &[u8], secret_key: &MlDsa65SecretKey) -> Result<MlDsa65Signature, RivideError>`
- `MlDsa65::verify(signature: &MlDsa65Signature, message: &[u8], public_key: &MlDsa65PublicKey) -> bool`
- `MlDsa87::keypair() -> Result<MlDsa87KeyPair, RivideError>`
- `MlDsa87::sign(message: &[u8], secret_key: &MlDsa87SecretKey) -> Result<MlDsa87Signature, RivideError>`
- `MlDsa87::verify(signature: &MlDsa87Signature, message: &[u8], public_key: &MlDsa87PublicKey) -> bool`

## 4. RAII Drop Safety

All secret key structures (`MlKem768SecretKey`, `MlKem1024SecretKey`, `MlDsa65SecretKey`, `MlDsa87SecretKey`) implement `Drop` and automatically invoke `rivide_cleanse` when leaving scope.
