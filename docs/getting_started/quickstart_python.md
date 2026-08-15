<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Quick Start: Python Integration via CTypes

This guide demonstrates how to load `librivide.so` or `librivide.dylib` in Python using standard `ctypes` without third-party C extension dependencies.

---

## 1. Compiling the Shared Library

```bash
# In the Rivide repository root:
make build BUILD_SHARED_LIBS=ON
# Produces build/librivide.so (Linux) or build/librivide.dylib (macOS)
```

---

## 2. Python Script (`rivide_pqc.py`)

```python
import ctypes
import os
import sys

# Buffer sizes for ML-KEM-768
PK_BYTES = 1184
SK_BYTES = 2400
CT_BYTES = 1088
SS_BYTES = 32

# Load shared library
lib = ctypes.CDLL("./build/librivide.so")

# Configure C function prototypes
lib.rivide_init.restype = ctypes.c_int
lib.rivide_init.argtypes = []

lib.rivide_ml_kem_768_keygen.restype = ctypes.c_int
lib.rivide_ml_kem_768_keygen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

lib.rivide_ml_kem_768_encaps.restype = ctypes.c_int
lib.rivide_ml_kem_768_encaps.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

lib.rivide_ml_kem_768_decaps.restype = ctypes.c_int
lib.rivide_ml_kem_768_decaps.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

# Initialize engine
if lib.rivide_init() != 0:
    print("Failed to initialize Rivide engine")
    sys.exit(1)

# Generate keypair
pk = ctypes.create_string_buffer(PK_BYTES)
sk = ctypes.create_string_buffer(SK_BYTES)
lib.rivide_ml_kem_768_keygen(pk, sk)

# Encapsulate
ct = ctypes.create_string_buffer(CT_BYTES)
ss_bob = ctypes.create_string_buffer(SS_BYTES)
lib.rivide_ml_kem_768_encaps(ct, ss_bob, pk)

# Decapsulate
ss_alice = ctypes.create_string_buffer(SS_BYTES)
lib.rivide_ml_kem_768_decaps(ss_alice, ct, sk)

assert ss_alice.raw == ss_bob.raw
print("[SUCCESS] Python ctypes established 256-bit quantum-safe key:", ss_alice.raw.hex()[:32] + "...")
```

---

## 3. Running the Script

```bash
python3 rivide_pqc.py
```
