# ML-KEM API Reference

The ML-KEM API provides keypair generation, encapsulation, and decapsulation for NIST FIPS 203 post-quantum key establishment.

Header: `#include "rivide/pqc/ml_kem.h"` or `#include "rivide/rivide.h"`

---

## Constants

### ML-KEM-768
*   `RIVIDE_ML_KEM_768_PK_BYTES`: `1184` (Public key byte size)
*   `RIVIDE_ML_KEM_768_SK_BYTES`: `2400` (Secret key byte size)
*   `RIVIDE_ML_KEM_768_CIPHERTEXT_BYTES`: `1088` (Ciphertext byte size)
*   `RIVIDE_ML_KEM_768_BYTES`: `32` (Shared secret byte size)

### ML-KEM-1024
*   `RIVIDE_ML_KEM_1024_PK_BYTES`: `1568`
*   `RIVIDE_ML_KEM_1024_SK_BYTES`: `3168`
*   `RIVIDE_ML_KEM_1024_CIPHERTEXT_BYTES`: `1568`
*   `RIVIDE_ML_KEM_1024_BYTES`: `32`

---

## Functions

### `rivide_ml_kem_768_keygen`
```c
rivide_status_t rivide_ml_kem_768_keygen(
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES],
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES]
);
```
Generates a new ML-KEM-768 public/secret keypair using system entropy.

---

### `rivide_ml_kem_768_encaps`
```c
rivide_status_t rivide_ml_kem_768_encaps(
    uint8_t ct[RIVIDE_ML_KEM_768_CIPHERTEXT_BYTES],
    uint8_t ss[RIVIDE_ML_KEM_768_BYTES],
    const uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES]
);
```
Encapsulates a 32-byte shared secret under public key `pk`, producing ciphertext `ct` and shared key `ss`.

---

### `rivide_ml_kem_768_decaps`
```c
rivide_status_t rivide_ml_kem_768_decaps(
    uint8_t ss[RIVIDE_ML_KEM_768_BYTES],
    const uint8_t ct[RIVIDE_ML_KEM_768_CIPHERTEXT_BYTES],
    const uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES]
);
```
Decapsulates ciphertext `ct` using secret key `sk`, recovering shared secret `ss`. Implements implicit rejection on corrupted ciphertexts.

---

### `rivide_ml_kem_1024_keygen` / `encaps` / `decaps`
Identical signature pattern using `1024` buffer constant identifiers.
