<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# C API Reference: Symmetric Cryptography & Memory Utilities

Public C99 declarations for SHA-3, SHAKE, AES-GCM AEAD, secure random generation, and constant-time memory utilities.

Headers: `<rivide/crypto/sha3.h>`, `<rivide/crypto/aes.h>`, `<rivide/utils/mem.h>`, `<rivide/utils/random.h>`

## 1. SHA-3 & SHAKE Functions

```c
void rivide_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen);
void rivide_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);
void rivide_shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void rivide_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
```

## 2. AES-GCM AEAD Functions

```c
rivide_status_t rivide_aes128_key_expand(rivide_aes_key_t *ctx, const uint8_t *key);
rivide_status_t rivide_aes256_key_expand(rivide_aes_key_t *ctx, const uint8_t *key);

rivide_status_t rivide_aes_gcm_encrypt(
    const rivide_aes_key_t *key,
    const uint8_t *iv,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *ct,
    uint8_t *tag
);

rivide_status_t rivide_aes_gcm_decrypt(
    const rivide_aes_key_t *key,
    const uint8_t *iv,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct,
    size_t ct_len,
    const uint8_t *tag,
    uint8_t *pt
);
```

## 3. Memory & Random Utilities

```c
/* Volatile memory zeroization barrier */
void rivide_cleanse(void *ptr, size_t len);

/* OS CSPRNG entropy generation */
rivide_status_t rivide_randombytes(uint8_t *buf, size_t len);

/* Constant-time memory comparison */
int rivide_ct_memcmp(const void *a, const void *b, size_t len);

/* Constant-time buffer selector */
void rivide_ct_select(uint8_t *dest, const uint8_t *a, const uint8_t *b, size_t len, uint8_t mask);
```
