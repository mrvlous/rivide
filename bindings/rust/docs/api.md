<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide Rust API Reference

Comprehensive API reference for the official **`rivide`** Rust crate.

## Installation

Add `rivide` to your `Cargo.toml`:

```toml
[dependencies]
rivide = "1.1.3"
```

Or via `cargo add`:

```bash
cargo add rivide
```

## Module Structure

```rust
use rivide::{
    // Top-level Modules
    kem::{MlKem768, MlKem1024, MlKem768KeyPair, MlKem1024KeyPair},
    dsa::{MlDsa65, MlDsa87, MlDsa65KeyPair, MlDsa87KeyPair, MlDsa65Signature, MlDsa87Signature},
    crypto::{Sha3, AesGcm, AesGcmResult},
    utils::{cleanse, ct_memcmp, get_cpu_features, randombytes, randombytes_into, version, CpuFeatures},
    error::RivideError,
};
```

## Constants & Buffer Dimensions

| Constant | Value (Bytes) | Description |
| :--- | :--- | :--- |
| `RIVIDE_ML_KEM_768_PK_BYTES` | `1184` | ML-KEM-768 Public Key Length |
| `RIVIDE_ML_KEM_768_SK_BYTES` | `2400` | ML-KEM-768 Secret Key Length |
| `RIVIDE_ML_KEM_768_CT_BYTES` | `1088` | ML-KEM-768 Ciphertext Length |
| `RIVIDE_ML_KEM_768_SS_BYTES` | `32` | ML-KEM Shared Secret Length |
| `RIVIDE_ML_KEM_1024_PK_BYTES` | `1568` | ML-KEM-1024 Public Key Length |
| `RIVIDE_ML_KEM_1024_SK_BYTES` | `3168` | ML-KEM-1024 Secret Key Length |
| `RIVIDE_ML_KEM_1024_CT_BYTES` | `1568` | ML-KEM-1024 Ciphertext Length |
| `RIVIDE_ML_KEM_1024_SS_BYTES` | `32` | ML-KEM Shared Secret Length |
| `RIVIDE_ML_DSA_65_PK_BYTES` | `1952` | ML-DSA-65 Public Key Length |
| `RIVIDE_ML_DSA_65_SK_BYTES` | `4032` | ML-DSA-65 Secret Key Length |
| `RIVIDE_ML_DSA_65_SIG_BYTES` | `3309` | ML-DSA-65 Signature Length |
| `RIVIDE_ML_DSA_87_PK_BYTES` | `2592` | ML-DSA-87 Public Key Length |
| `RIVIDE_ML_DSA_87_SK_BYTES` | `4896` | ML-DSA-87 Secret Key Length |
| `RIVIDE_ML_DSA_87_SIG_BYTES` | `4627` | ML-DSA-87 Signature Length |
| `RIVIDE_SHA3_256_DIGEST_LENGTH` | `32` | SHA3-256 Output Digest Length |
| `RIVIDE_SHA3_512_DIGEST_LENGTH` | `64` | SHA3-512 Output Digest Length |
| `RIVIDE_AES_GCM_IV_BYTES` | `12` | AES-GCM Recommended Nonce (IV) Length |
| `RIVIDE_AES_GCM_TAG_BYTES` | `16` | AES-GCM Authentication Tag Length |

## Key Encapsulation Mechanism (`rivide::kem`)

### `MlKem768` (NIST FIPS 203, Category 3)

#### `MlKem768::keypair() -> Result<MlKem768KeyPair, RivideError>`
Generates a new ML-KEM-768 public and secret keypair from OS CSPRNG entropy.

#### `MlKem768::encapsulate(public_key: &MlKem768PublicKey) -> Result<MlKem768EncapsResult, RivideError>`
Encapsulates a 32-byte quantum-safe shared secret under the provided public key.

#### `MlKem768::decapsulate(ciphertext: &[u8; 1088], secret_key: &MlKem768SecretKey) -> Result<[u8; 32], RivideError>`
Decapsulates the 32-byte shared secret from the ciphertext in constant time.

### `MlKem1024` (NIST FIPS 203, Category 5)

#### `MlKem1024::keypair() -> Result<MlKem1024KeyPair, RivideError>`
Generates a new ML-KEM-1024 public and secret keypair.

#### `MlKem1024::encapsulate(public_key: &MlKem1024PublicKey) -> Result<MlKem1024EncapsResult, RivideError>`
Encapsulates a 32-byte shared secret under the provided public key.

#### `MlKem1024::decapsulate(ciphertext: &[u8; 1568], secret_key: &MlKem1024SecretKey) -> Result<[u8; 32], RivideError>`
Decapsulates the 32-byte shared secret from the ciphertext in constant time.

## Digital Signature Algorithm (`rivide::dsa`)

### `MlDsa65` (NIST FIPS 204, Category 3)

#### `MlDsa65::keypair() -> Result<MlDsa65KeyPair, RivideError>`
Generates a new ML-DSA-65 signing keypair.

#### `MlDsa65::sign(message: &[u8], secret_key: &MlDsa65SecretKey) -> Result<MlDsa65Signature, RivideError>`
Computes a 3309-byte digital signature over the message slice.

#### `MlDsa65::verify(signature: &MlDsa65Signature, message: &[u8], public_key: &MlDsa65PublicKey) -> bool`
Verifies signature validity in constant time. Returns `true` if authentic, `false` otherwise.

### `MlDsa87` (NIST FIPS 204, Category 5)

#### `MlDsa87::keypair() -> Result<MlDsa87KeyPair, RivideError>`
Generates a new ML-DSA-87 signing keypair.

#### `MlDsa87::sign(message: &[u8], secret_key: &MlDsa87SecretKey) -> Result<MlDsa87Signature, RivideError>`
Computes a 4627-byte digital signature over the message slice.

#### `MlDsa87::verify(signature: &MlDsa87Signature, message: &[u8], public_key: &MlDsa87PublicKey) -> bool`
Verifies signature validity in constant time. Returns `true` if authentic, `false` otherwise.

## Symmetric Primitives (`rivide::crypto`)

### `Sha3` (NIST FIPS 202)
- `Sha3::sha3_256(data: &[u8]) -> [u8; 32]`
- `Sha3::sha3_512(data: &[u8]) -> [u8; 64]`
- `Sha3::shake128(data: &[u8], output_len: usize) -> Vec<u8>`
- `Sha3::shake256(data: &[u8], output_len: usize) -> Vec<u8>`

### `AesGcm` (NIST SP 800-38D)
- `AesGcm::encrypt_128(key: &[u8; 16], iv: &[u8; 12], plaintext: &[u8], aad: Option<&[u8]>) -> Result<AesGcmResult, RivideError>`
- `AesGcm::decrypt_128(key: &[u8; 16], iv: &[u8; 12], ciphertext: &[u8], tag: &[u8; 16], aad: Option<&[u8]>) -> Result<Vec<u8>, RivideError>`
- `AesGcm::encrypt_256(key: &[u8; 32], iv: &[u8; 12], plaintext: &[u8], aad: Option<&[u8]>) -> Result<AesGcmResult, RivideError>`
- `AesGcm::decrypt_256(key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8], tag: &[u8; 16], aad: Option<&[u8]>) -> Result<Vec<u8>, RivideError>`

## Utilities & Memory Safety (`rivide::utils`)

- `cleanse(buffer: &mut [u8])`: Volatile memory zeroization preventing dead-store elimination.
- `randombytes(len: usize) -> Result<Vec<u8>, RivideError>`: Generates cryptographically secure random bytes from OS CSPRNG.
- `randombytes_into(buffer: &mut [u8]) -> Result<(), RivideError>`: Fills an existing buffer with OS CSPRNG entropy.
- `ct_memcmp(a: &[u8], b: &[u8]) -> i32`: Compares two byte slices in constant time. Returns `0` if equal.
- `get_cpu_features() -> CpuFeatures`: Returns hardware SIMD acceleration capability bitmask.
- `version() -> &'static str`: Returns library version string (`"1.1.0"`).
