# Symmetric Cryptography & Utility API Reference

This document covers public APIs for SHA-3 hashing, SHAKE XOFs, AES-GCM AEAD encryption, memory cleansing, and random byte generation.

Headers:
*   `#include "rivide/crypto/sha3.h"`
*   `#include "rivide/crypto/aes_gcm.h"`
*   `#include "rivide/utils/mem.h"`
*   `#include "rivide/utils/random.h"`

---

## 1. SHA-3 & SHAKE Hashing API

### `rivide_sha3_256` / `rivide_sha3_512`
```c
rivide_status_t rivide_sha3_256(
    uint8_t out[32],
    const uint8_t *in,
    size_t inlen
);

rivide_status_t rivide_sha3_512(
    uint8_t out[64],
    const uint8_t *in,
    size_t inlen
);
```
Computes one-shot SHA3-256 (32 bytes) or SHA3-512 (64 bytes) message digest over input buffer `in`.

---

### `rivide_shake128` / `rivide_shake256`
```c
rivide_status_t rivide_shake128(
    uint8_t *out,
    size_t outlen,
    const uint8_t *in,
    size_t inlen
);

rivide_status_t rivide_shake256(
    uint8_t *out,
    size_t outlen,
    const uint8_t *in,
    size_t inlen
);
```
Computes extendable-output function (XOF) producing `outlen` bytes of pseudorandom output from input `in`.

---

## 2. AES-GCM AEAD Encryption API

### `rivide_aes_gcm_encrypt`
```c
rivide_status_t rivide_aes_gcm_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *key,
    size_t key_len
);
```
Encrypts `plaintext` under AES-GCM key (`key_len` = 16 or 32 bytes) with `nonce` and optional `aad`, outputting `ciphertext` and 16-byte authentication `tag`.

---

### `rivide_aes_gcm_decrypt`
```c
rivide_status_t rivide_aes_gcm_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *key,
    size_t key_len
);
```
Decrypts `ciphertext` and verifies 16-byte `tag`. Returns `RIVIDE_SUCCESS` or `RIVIDE_ERR_BAD_SIGNATURE` if authentication fails.

---

## 3. Memory & Randomness Utilities API

### `rivide_cleanse`
```c
void rivide_cleanse(void *v, size_t len);
```
Securely zeroes memory buffer `v` preventing compiler dead-store elimination.

---

### `rivide_ct_memcmp`
```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len);
```
Constant-time memory comparison. Returns `0` if equal, non-zero if different.

---

### `rivide_randombytes`
```c
rivide_status_t rivide_randombytes(uint8_t *buf, size_t len);
```
Fills buffer `buf` with `len` cryptographically secure random bytes from system entropy.
