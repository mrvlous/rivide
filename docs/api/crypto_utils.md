# Symmetric Crypto & Utility API Reference

Public API functions for SHA-3, SHAKE XOF, AES-GCM, and constant-time memory helpers (`include/rivide/crypto/sha3.h`, `include/rivide/crypto/aes_gcm.h`, `include/rivide/utils/mem.h`).

## Header Files
```c
#include "rivide/crypto/sha3.h"
#include "rivide/crypto/aes_gcm.h"
#include "rivide/utils/mem.h"
```

## SHA-3 & SHAKE Hashing API

### `rivide_sha3_256`
Computes a 32-byte SHA3-256 message digest.

```c
void rivide_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen);
```

### `rivide_sha3_512`
Computes a 64-byte SHA3-512 message digest.

```c
void rivide_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);
```

### `rivide_shake128`
Computes an extendable-output function (XOF) value using SHAKE-128.

```c
void rivide_shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
```

### `rivide_shake256`
Computes an extendable-output function (XOF) value using SHAKE-256.

```c
void rivide_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
```

---

## AES-GCM Authenticated Encryption API

### `rivide_aes128_gcm_encrypt`
Encrypts and authenticates plaintext using AES-128-GCM.

```c
rivide_status_t rivide_aes128_gcm_encrypt(uint8_t *ct, uint8_t tag[16],
                                          const uint8_t *pt, size_t ptlen,
                                          const uint8_t *aad, size_t aadlen,
                                          const uint8_t key[16], const uint8_t iv[12]);
```

### `rivide_aes256_gcm_encrypt`
Encrypts and authenticates plaintext using AES-256-GCM.

```c
rivide_status_t rivide_aes256_gcm_encrypt(uint8_t *ct, uint8_t tag[16],
                                          const uint8_t *pt, size_t ptlen,
                                          const uint8_t *aad, size_t aadlen,
                                          const uint8_t key[32], const uint8_t iv[12]);
```

---

## Constant-Time Memory Utility API

### `rivide_ct_memcmp`
Compares two memory buffers in constant time.

```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len);
```
- **Returns**: `0` if equal, non-zero if different.

### `rivide_ct_select`
Copies `a` or `b` into `r` in constant time depending on `choice`.

```c
void rivide_ct_select(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len, int choice);
```
