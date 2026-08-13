# Memory & Randomness Subsystem Architecture

This document describes Rivide's secure memory handling, constant-time operations, and operating system entropy generation routines.

## Secure Memory Cleansing (`rivide_cleanse`)

To prevent secret leakage via cold-boot attacks or compiler optimizations, sensitive data buffers are scrubbed using `rivide_cleanse`:

```c
void rivide_cleanse(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
```

> [!IMPORTANT]
> The `volatile` pointer qualifier ensures that compiler optimizations (such as dead-store elimination) do NOT strip memory wiping calls.

## Constant-Time Operations

To prevent side-channel timing leakage, secret byte arrays are compared and selected using constant-time algorithms:

1. **`rivide_ct_memcmp(const void *a, const void *b, size_t len)`**:
   - Performs a byte-by-byte XOR comparison over all `len` bytes regardless of where differences occur.
   - Returns `0` if equal, non-zero if different.

2. **`rivide_ct_select(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len, int choice)`**:
   - Copies `a` into `r` if `choice == 0`, or `b` into `r` if `choice != 0`.
   - Uses bitwise masks without branch instructions:
     ```c
     uint8_t mask = (uint8_t)(-(choice != 0));
     r[i] = (a[i] & ~mask) | (b[i] & mask);
     ```

## OS Random Entropy Source (`rivide_randombytes`)

Cryptographic keys and nonces require cryptographically secure random bytes from OS entropy pools:

- **Linux / Android**: `getrandom()` system call or `/dev/urandom`.
- **macOS / iOS / BSD**: `arc4random_buf()`.
- **Windows**: `BCryptGenRandom()`.
