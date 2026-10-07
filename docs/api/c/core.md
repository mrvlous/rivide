<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# C API Reference: Core Initialization & Utilities

Public C99 declarations for engine initialization, status error codes, and library metadata.

Header: `<rivide/rivide.h>`

## 1. Engine Initialization

```c
rivide_status_t rivide_init(void);
```

Initializes the Rivide cryptographic engine, validates internal constants, and performs runtime CPU capability detection.

- **Returns**: `RIVIDE_SUCCESS` (0) on success, or negative error code on failure.

## 2. Version Information

```c
const char *rivide_version_string(void);
```

- `rivide_version_string()`: Returns static semantic version string (e.g. `"1.1.7"`).

## 3. Status Error Codes

Header: `<rivide/rivide_types.h>`

| Status Macro | Integer Value | Description |
| :--- | :--- | :--- |
| `RIVIDE_SUCCESS` | `0` | Operation completed successfully |
| `RIVIDE_ERR_NULL_PTR` | `-1` | A required pointer argument was NULL |
| `RIVIDE_ERR_INVALID_PARAM` | `-2` | Argument value out of acceptable range |
| `RIVIDE_ERR_RNG_FAILURE` | `-3` | Operating system CSPRNG failed to produce entropy |
| `RIVIDE_ERR_VERIFICATION_FAILED` | `-4` | Digital signature verification or authentication tag failed |
| `RIVIDE_ERR_DECAPSULATION_FAILED` | `-5` | KEM decapsulation failed (implicit rejection triggered) |
| `RIVIDE_ERR_UNSUPPORTED` | `-6` | Requested feature or algorithm not compiled in |
| `RIVIDE_ERR_INTERNAL` | `-7` | Internal cryptographic state fault |

## 4. Status String Representation

```c
const char *rivide_status_str(rivide_status_t status);
```

- Converts a `rivide_status_t` status code into a static, human-readable error description string (e.g. `"Success"`, `"Invalid parameter"`, `"Verification failed"`). The returned pointer is valid for the program lifetime.
