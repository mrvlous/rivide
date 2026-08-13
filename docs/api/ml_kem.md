# ML-KEM API Reference (NIST FIPS 203)

Public API functions for ML-KEM-768 and ML-KEM-1024 Key Encapsulation Mechanism (`include/rivide/pqc/ml_kem.h`).

## Header File
```c
#include "rivide/pqc/ml_kem.h"
```

## Constants & Buffer Sizes

### ML-KEM-768 Constants
- `RIVIDE_ML_KEM_768_PK_BYTES`: `1184` bytes.
- `RIVIDE_ML_KEM_768_SK_BYTES`: `2400` bytes.
- `RIVIDE_ML_KEM_768_CT_BYTES`: `1088` bytes.
- `RIVIDE_ML_KEM_768_SS_BYTES`: `32` bytes.

### ML-KEM-1024 Constants
- `RIVIDE_ML_KEM_1024_PK_BYTES`: `1568` bytes.
- `RIVIDE_ML_KEM_1024_SK_BYTES`: `3168` bytes.
- `RIVIDE_ML_KEM_1024_CT_BYTES`: `1568` bytes.
- `RIVIDE_ML_KEM_1024_SS_BYTES`: `32` bytes.

## ML-KEM-768 Functions

### `rivide_ml_kem_768_keygen`
Generates an ML-KEM-768 public and secret keypair.

```c
rivide_status_t rivide_ml_kem_768_keygen(uint8_t *pk, uint8_t *sk);
```
- **`pk`**: Output public key buffer (1184 bytes).
- **`sk`**: Output secret key buffer (2400 bytes).

### `rivide_ml_kem_768_encaps`
Encapsulates a 32-byte shared key using the recipient's public key.

```c
rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
```
- **`ct`**: Output ciphertext buffer (1088 bytes).
- **`ss`**: Output shared key buffer (32 bytes).
- **`pk`**: Input recipient public key (1184 bytes).

### `rivide_ml_kem_768_decaps`
Decapsulates a ciphertext using the recipient's secret key.

```c
rivide_status_t rivide_ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```
- **`ss`**: Output decapsulated shared key buffer (32 bytes).
- **`ct`**: Input ciphertext buffer (1088 bytes).
- **`sk`**: Input recipient secret key (2400 bytes).

---

## ML-KEM-1024 Functions

### `rivide_ml_kem_1024_keygen`
```c
rivide_status_t rivide_ml_kem_1024_keygen(uint8_t *pk, uint8_t *sk);
```

### `rivide_ml_kem_1024_encaps`
```c
rivide_status_t rivide_ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
```

### `rivide_ml_kem_1024_decaps`
```c
rivide_status_t rivide_ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```
