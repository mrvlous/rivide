<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# C API Reference: NIST FIPS 203 ML-KEM

Public C99 declarations for Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM**).

Header: `<rivide/pqc/ml_kem.h>`

## 1. Buffer Size Constants

| Constant Macro | ML-KEM-768 | ML-KEM-1024 |
| :--- | :--- | :--- |
| `RIVIDE_ML_KEM_*_PUBLICKEYBYTES` | `1184` bytes | `1568` bytes |
| `RIVIDE_ML_KEM_*_SECRETKEYBYTES` | `2400` bytes | `3168` bytes |
| `RIVIDE_ML_KEM_*_CIPHERTEXTBYTES` | `1088` bytes | `1568` bytes |
| `RIVIDE_ML_KEM_BYTES` | `32` bytes | `32` bytes |

## 2. ML-KEM-768 Functions

```c
rivide_status_t rivide_ml_kem_768_keygen(uint8_t *pk, uint8_t *sk);
rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
rivide_status_t rivide_ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

- **`keygen`**: Generates a public key (`1184` bytes) and secret key (`2400` bytes).
- **`encaps`**: Generates a ciphertext (`1088` bytes) and shared secret (`32` bytes) using public key.
- **`decaps`**: Decapsulates the shared secret (`32` bytes) from ciphertext in constant time.

## 3. ML-KEM-1024 Functions

```c
rivide_status_t rivide_ml_kem_1024_keygen(uint8_t *pk, uint8_t *sk);
rivide_status_t rivide_ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
rivide_status_t rivide_ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```
