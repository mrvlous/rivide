# Symmetric Crypto & Utility API Reference

Public API functions for SHA-3, SHAKE XOF, AES-GCM AEAD, and constant-time memory helpers (`include/rivide/crypto/sha3.h`, `include/rivide/crypto/aes_gcm.h`, `include/rivide/utils/mem.h`).

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

### Incremental SHAKE Streaming API

```c
void rivide_shake128_init(rivide_keccak_state_t *ctx);
void rivide_shake256_init(rivide_keccak_state_t *ctx);
void rivide_shake_absorb(rivide_keccak_state_t *ctx, const uint8_t *in, size_t inlen);
void rivide_shake_squeeze(rivide_keccak_state_t *ctx, uint8_t *out, size_t outlen);
```

---

## AES-GCM Authenticated Encryption API

### Key Expansion

```c
rivide_status_t rivide_aes128_key_expand(rivide_aes_key_t *key, const uint8_t *user_key);
rivide_status_t rivide_aes256_key_expand(rivide_aes_key_t *key, const uint8_t *user_key);
```

### `rivide_aes_gcm_encrypt`
Encrypts plaintext and computes a 16-byte authentication tag over ciphertext and associated data.

```c
rivide_status_t rivide_aes_gcm_encrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *pt, size_t pt_len,
                                       uint8_t *ct, uint8_t *tag);
```

### `rivide_aes_gcm_decrypt`
Decrypts ciphertext and verifies the 16-byte authentication tag in constant time.

```c
rivide_status_t rivide_aes_gcm_decrypt(const rivide_aes_key_t *key, const uint8_t *iv,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *ct, size_t ct_len,
                                       const uint8_t *tag, uint8_t *pt);
```

---

## Constant-Time Memory Utility API

### `rivide_cleanse`
Securely wipes memory buffers using volatile memory barrier to prevent dead-store elimination.

```c
void rivide_cleanse(void *ptr, size_t len);
```

### `rivide_ct_memcmp`
Compares two memory buffers in constant time.

```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len);
```
- **Returns**: `0` if equal, non-zero if different.

### `rivide_ct_select`
Copies `len` bytes from `src_a` (if `selector` is 0) or `src_b` (if `selector` is non-zero) into `dst` in constant time without conditional branching.

```c
void rivide_ct_select(void *dst, const void *src_a, const void *src_b, size_t len, int selector);
```
