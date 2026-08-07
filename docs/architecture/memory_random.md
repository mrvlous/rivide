# Memory Cleansing and CSPRNG Subsystems

This document details the constant-time memory utilities, secure memory zeroization, and multi-platform Cryptographically Secure Pseudorandom Number Generator (CSPRNG) architecture implemented in [`src/utils/mem.c`](../../src/utils/mem.c) and [`src/utils/random.c`](../../src/utils/random.c).

---

## 1. Constant-Time Memory Utilities

In cryptographic implementations, comparison operations on sensitive data (such as private keys or MAC tags) must not leak key information through timing variations.

### Constant-Time Byte Comparison (`rivide_ct_memcmp`)
Compares two byte arrays in execution time proportional strictly to buffer length $N$, independent of buffer content:
```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (pa[i] ^ pb[i]);
    }
    return (diff == 0) ? 0 : 1;
}
```

### Constant-Time Conditional Select (`rivide_ct_select`)
Copies buffer `src` to `dst` if mask condition `condition_mask` is set (`0xFF`), otherwise leaves `dst` untouched, without branching instructions:
```c
void rivide_ct_select(uint8_t *dst, const uint8_t *src, size_t len, uint8_t mask) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= mask & (src[i] ^ dst[i]);
    }
}
```

---

## 2. Secure Memory Cleansing (`rivide_cleanse`)

Optimizing compilers (such as GCC with `-O3` or Clang) often eliminate standard `memset` calls if the zeroed variable is not accessed again before leaving scope.

Rivide guarantees memory erasure by inserting compiler memory barriers:
```c
void rivide_cleanse(void *v, size_t len) {
    if (!v || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (len--) {
        *p++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(v) : "memory");
#endif
}
```

---

## 3. Platform CSPRNG Entropy Engine

Randomness is critical for post-quantum key generation, encapsulation seeds, and rejection sampling masks. Rivide queries OS kernel entropy sources natively:

```
                          rivide_randombytes(buf, len)
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
     [ Linux Kernel ]                                      [ Windows OS ]
  getrandom(GRND_NONBLOCK)                                BCryptGenRandom(...)
            │                                                     │
            └──────────────────────────┬──────────────────────────┘
                                       ▼
                       Fallback: /dev/urandom POSIX stream
```

### Bare-Metal & Custom Randomness Callbacks
For embedded microcontrollers or specialized operating environments, Rivide allows developers to register custom entropy callbacks via `rivide_set_random_callback()`.
