# Core API Reference

The Core API provides library initialization, version reporting, CPU feature detection, and status code string translation.

Header: `#include "rivide/rivide.h"` or `#include "rivide/rivide_types.h"`

---

## Functions

### `rivide_init`
```c
rivide_status_t rivide_init(void);
```
Initializes internal state, performs platform CSPRNG availability checks, and queries CPU capabilities. Must be called once before invoking cryptographic routines.

*   **Returns**:
    *   `RIVIDE_SUCCESS` on successful initialization.
    *   `RIVIDE_ERR_ENTROPY_FAILED` if system entropy source is unavailable.

---

### `rivide_version_string`
```c
const char *rivide_version_string(void);
```
Returns a null-terminated semantic version string (e.g. `"0.1.0"`).

---

### `rivide_status_str`
```c
const char *rivide_status_str(rivide_status_t status);
```
Translates a `rivide_status_t` error code into a human-readable English description string.

*   **Parameters**:
    *   `status`: Status return value.
*   **Returns**: Pointer to static description string.

---

## Status Codes (`rivide_status_t`)

| Code | Value | Description |
| :--- | :--- | :--- |
| `RIVIDE_SUCCESS` | `0` | Operation completed successfully |
| `RIVIDE_ERR_INVALID_PARAM` | `-1` | Invalid argument, null pointer, or size mismatch |
| `RIVIDE_ERR_BAD_SIGNATURE` | `-2` | Digital signature verification failed |
| `RIVIDE_ERR_BUFFER_TOO_SMALL` | `-3` | Output buffer size is insufficient |
| `RIVIDE_ERR_ENTROPY_FAILED` | `-4` | System CSPRNG failed to supply entropy |
| `RIVIDE_ERR_INTERNAL` | `-99` | Unexpected internal library state error |
