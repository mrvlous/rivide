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
uint32_t rivide_version_number(void);
```

- `rivide_version_string()`: Returns static semantic version string (e.g. `"1.1.4"`).
- `rivide_version_number()`: Returns packed 32-bit integer version (`0x010104`).

## 3. Status Error Codes

| Status Macro | Integer Value | Description |
| :--- | :--- | :--- |
| `RIVIDE_SUCCESS` | `0` | Operation completed successfully |
| `RIVIDE_ERR_INVALID_PARAM` | `-1` | Invalid null pointer or out-of-bounds parameter |
| `RIVIDE_ERR_VERIFICATION_FAILED` | `-2` | Signature verification or authentication tag failed |
| `RIVIDE_ERR_ENTROPY_FAILURE` | `-3` | Operating system CSPRNG failure |
| `RIVIDE_ERR_INTERNAL` | `-4` | Internal cryptographic state fault |
