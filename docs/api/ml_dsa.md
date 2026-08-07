# ML-DSA API Reference

The ML-DSA API provides keypair generation, signature generation, and verification for NIST FIPS 204 post-quantum digital signatures.

Header: `#include "rivide/pqc/ml_dsa.h"` or `#include "rivide/rivide.h"`

---

## Constants

### ML-DSA-65
*   `RIVIDE_ML_DSA_65_PK_BYTES`: `1952` (Public key byte size)
*   `RIVIDE_ML_DSA_65_SK_BYTES`: `4032` (Secret key byte size)
*   `RIVIDE_ML_DSA_65_SIG_BYTES`: `3309` (Maximum signature byte size)

### ML-DSA-87
*   `RIVIDE_ML_DSA_87_PK_BYTES`: `2592`
*   `RIVIDE_ML_DSA_87_SK_BYTES`: `4896`
*   `RIVIDE_ML_DSA_87_SIG_BYTES`: `4627`

---

## Functions

### `rivide_ml_dsa_65_keygen`
```c
rivide_status_t rivide_ml_dsa_65_keygen(
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES],
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES]
);
```
Generates a new ML-DSA-65 signing keypair using system entropy.

---

### `rivide_ml_dsa_65_sign`
```c
rivide_status_t rivide_ml_dsa_65_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES]
);
```
Signs message buffer `msg` using secret key `sk`, writing signature into `sig` and returning byte length in `siglen`.

---

### `rivide_ml_dsa_65_verify`
```c
rivide_status_t rivide_ml_dsa_65_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES]
);
```
Verifies signature `sig` against message `msg` using public key `pk`.

*   **Returns**:
    *   `RIVIDE_SUCCESS` if signature is valid.
    *   `RIVIDE_ERR_BAD_SIGNATURE` if verification fails.

---

### `rivide_ml_dsa_87_keygen` / `sign` / `verify`
Identical signature pattern using `87` buffer constant identifiers.
