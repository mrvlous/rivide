# ML-DSA API Reference (NIST FIPS 204)

Public API functions for ML-DSA-65 and ML-DSA-87 Digital Signature Algorithm (`include/rivide/pqc/ml_dsa.h`).

## Header File
```c
#include "rivide/pqc/ml_dsa.h"
```

## Constants & Buffer Sizes

### ML-DSA-65 Constants
- `RIVIDE_ML_DSA_65_PK_BYTES`: `1952` bytes.
- `RIVIDE_ML_DSA_65_SK_BYTES`: `4032` bytes.
- `RIVIDE_ML_DSA_65_SIG_BYTES`: `3309` bytes.

### ML-DSA-87 Constants
- `RIVIDE_ML_DSA_87_PK_BYTES`: `2592` bytes.
- `RIVIDE_ML_DSA_87_SK_BYTES`: `4896` bytes.
- `RIVIDE_ML_DSA_87_SIG_BYTES`: `4627` bytes.

## ML-DSA-65 Functions

### `rivide_ml_dsa_65_keygen`
Generates an ML-DSA-65 public and secret keypair.

```c
rivide_status_t rivide_ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk);
```
- **`pk`**: Output public key buffer (1952 bytes).
- **`sk`**: Output secret key buffer (4032 bytes).

### `rivide_ml_dsa_65_sign`
Signs a message using the signer's secret key.

```c
rivide_status_t rivide_ml_dsa_65_sign(uint8_t *sig, size_t *siglen,
                                      const uint8_t *msg, size_t msglen,
                                      const uint8_t *sk);
```
- **`sig`**: Output signature buffer (3309 bytes).
- **`siglen`**: Pointer receiving actual signature byte length.
- **`msg`**: Input message buffer pointer.
- **`msglen`**: Input message byte length.
- **`sk`**: Input signer secret key (4032 bytes).

### `rivide_ml_dsa_65_verify`
Verifies a digital signature against a message and public key.

```c
rivide_status_t rivide_ml_dsa_65_verify(const uint8_t *sig, size_t siglen,
                                        const uint8_t *msg, size_t msglen,
                                        const uint8_t *pk);
```
- **`sig`**: Input signature buffer (3309 bytes).
- **`siglen`**: Byte length of signature (must equal `RIVIDE_ML_DSA_65_SIG_BYTES` = 3309).
- **`msg`**: Input message buffer pointer.
- **`msglen`**: Input message byte length.
- **`pk`**: Input signer public key (1952 bytes).
- **Returns**: `RIVIDE_SUCCESS` if signature is valid, or `RIVIDE_ERR_VERIFICATION_FAILED` if signature is invalid or `siglen` does not match the exact expected size.

---

## ML-DSA-87 Functions

### `rivide_ml_dsa_87_keygen`
Generates an ML-DSA-87 public and secret keypair.

```c
rivide_status_t rivide_ml_dsa_87_keygen(uint8_t *pk, uint8_t *sk);
```
- **`pk`**: Output public key buffer (2592 bytes).
- **`sk`**: Output secret key buffer (4896 bytes).

### `rivide_ml_dsa_87_sign`
Signs a message using the signer's secret key.

```c
rivide_status_t rivide_ml_dsa_87_sign(uint8_t *sig, size_t *siglen,
                                      const uint8_t *msg, size_t msglen,
                                      const uint8_t *sk);
```
- **`sig`**: Output signature buffer (4627 bytes).
- **`siglen`**: Pointer receiving actual signature byte length.
- **`msg`**: Input message buffer pointer.
- **`msglen`**: Input message byte length.
- **`sk`**: Input signer secret key (4896 bytes).

### `rivide_ml_dsa_87_verify`
Verifies a digital signature against a message and public key.

```c
rivide_status_t rivide_ml_dsa_87_verify(const uint8_t *sig, size_t siglen,
                                        const uint8_t *msg, size_t msglen,
                                        const uint8_t *pk);
```
- **`sig`**: Input signature buffer (4627 bytes).
- **`siglen`**: Byte length of signature (must equal `RIVIDE_ML_DSA_87_SIG_BYTES` = 4627).
- **`msg`**: Input message buffer pointer.
- **`msglen`**: Input message byte length.
- **`pk`**: Input signer public key (2592 bytes).
- **Returns**: `RIVIDE_SUCCESS` if signature is valid, or `RIVIDE_ERR_VERIFICATION_FAILED` if signature is invalid or `siglen` does not match the exact expected size.
