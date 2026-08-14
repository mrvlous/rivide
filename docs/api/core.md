# Core API Reference

The Core API provides library initialization, status codes, and security memory management routines (`include/rivide/rivide.h`).

## Header File
```c
#include "rivide/rivide.h"
```

## Status Codes (`rivide_status_t`)

```c
typedef enum rivide_status {
    RIVIDE_SUCCESS                  =  0,
    RIVIDE_ERR_NULL_PTR             = -1,
    RIVIDE_ERR_INVALID_PARAM        = -2,
    RIVIDE_ERR_RNG_FAILURE          = -3,
    RIVIDE_ERR_VERIFICATION_FAILED  = -4,
    RIVIDE_ERR_DECAPSULATION_FAILED = -5,
    RIVIDE_ERR_UNSUPPORTED          = -6,
    RIVIDE_ERR_INTERNAL             = -7
} rivide_status_t;
```

## Functions

### `rivide_init`
Initializes global library state and queries underlying CPU hardware acceleration capabilities.

```c
rivide_status_t rivide_init(void);
```
- **Returns**: `RIVIDE_SUCCESS` on success.

### `rivide_status_str`
Returns a human-readable description of a status code.

```c
const char *rivide_status_str(rivide_status_t status);
```
- **`status`**: The status code to convert.
- **Returns**: Static null-terminated string describing the status.

### `rivide_cleanse`
Securely wipes a buffer in memory to prevent secret leakage.

```c
void rivide_cleanse(void *ptr, size_t len);
```
- **`ptr`**: Pointer to memory buffer to cleanse.
- **`len`**: Number of bytes to wipe.

### `rivide_randombytes`
Fills a buffer with cryptographically secure random bytes from the operating system entropy pool.

```c
rivide_status_t rivide_randombytes(uint8_t *out, size_t len);
```
- **`out`**: Destination byte buffer.
- **`len`**: Number of bytes to generate.
- **Returns**: `RIVIDE_SUCCESS` on success, `RIVIDE_ERR_RNG_FAILURE` if OS entropy generation failed.
