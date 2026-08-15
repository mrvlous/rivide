<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# C API Reference: NIST FIPS 204 ML-DSA

Public C99 declarations for Module-Lattice-Based Digital Signature Algorithm (**ML-DSA**).

Header: `<rivide/pqc/ml_dsa.h>`

---

## 1. Buffer Size Constants

| Constant Macro | ML-DSA-65 | ML-DSA-87 |
| :--- | :--- | :--- |
| `RIVIDE_ML_DSA_*_PUBLICKEYBYTES` | `1952` bytes | `2592` bytes |
| `RIVIDE_ML_DSA_*_SECRETKEYBYTES` | `4032` bytes | `4896` bytes |
| `RIVIDE_ML_DSA_*_BYTES` (Signature) | `3309` bytes | `4627` bytes |

---

## 2. ML-DSA-65 Functions

```c
rivide_status_t rivide_ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk);

rivide_status_t rivide_ml_dsa_65_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *sk
);

rivide_status_t rivide_ml_dsa_65_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *pk
);
```

- **`keygen`**: Generates a public key (`1952` bytes) and secret key (`4032` bytes).
- **`sign`**: Generates signature (`3309` bytes) over `msg`.
- **`verify`**: Verifies signature authenticity. Returns `RIVIDE_SUCCESS` (0) on valid signature, or `RIVIDE_ERR_VERIFICATION_FAILED` (-2) on invalid signature.

---

## 3. ML-DSA-87 Functions

```c
rivide_status_t rivide_ml_dsa_87_keygen(uint8_t *pk, uint8_t *sk);

rivide_status_t rivide_ml_dsa_87_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *sk
);

rivide_status_t rivide_ml_dsa_87_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *pk
);
```
