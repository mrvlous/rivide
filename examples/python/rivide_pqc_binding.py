# SPDX-License-Identifier: MIT
#
# Rivide Post-Quantum Cryptography Library
# Copyright (C) 2026 Moh. Ananda Firmansyah Putra
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""
Python ctypes wrapper example demonstrating Rivide Post-Quantum Cryptography APIs.

Provides Python bindings for ML-KEM-768 key encapsulation and ML-DSA-65 digital
signature verification by dynamically loading librivide.so / librivide.dylib.
"""

import ctypes
import os
import sys

# Buffer size constants from Rivide C headers
RIVIDE_ML_KEM_768_PUBLICKEYBYTES = 1184
RIVIDE_ML_KEM_768_SECRETKEYBYTES = 2400
RIVIDE_ML_KEM_768_CIPHERTEXTBYTES = 1088
RIVIDE_ML_KEM_BYTES = 32

RIVIDE_ML_DSA_65_PUBLICKEYBYTES = 1952
RIVIDE_ML_DSA_65_SECRETKEYBYTES = 4032
RIVIDE_ML_DSA_65_BYTES = 3309


def load_rivide_library():
    """Locate and load the compiled Rivide shared library."""
    lib_names = ["librivide.so", "librivide.dylib", "rivide.dll"]
    search_paths = [
        ".",
        "./build",
        "../build",
        "../../build",
        "/usr/local/lib",
    ]

    for path in search_paths:
        for name in lib_names:
            full_path = os.path.join(path, name)
            if os.path.exists(full_path):
                try:
                    return ctypes.CDLL(os.path.abspath(full_path))
                except OSError:
                    continue
    return None


def main():
    print("Rivide Python CTypes PQC Integration Example")

    lib = load_rivide_library()
    if not lib:
        print("[NOTICE] Shared library (librivide.so) not found in build paths.")
        print("         Run 'make build' first to compile librivide.so.")
        return 0

    # Bind rivide_init
    lib.rivide_init.restype = ctypes.c_int
    lib.rivide_init.argtypes = []

    # Bind rivide_version_string
    lib.rivide_version_string.restype = ctypes.c_char_p
    lib.rivide_version_string.argtypes = []

    # Bind ML-KEM-768 APIs
    lib.rivide_ml_kem_768_keypair.restype = ctypes.c_int
    lib.rivide_ml_kem_768_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

    lib.rivide_ml_kem_768_encaps.restype = ctypes.c_int
    lib.rivide_ml_kem_768_encaps.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    lib.rivide_ml_kem_768_decaps.restype = ctypes.c_int
    lib.rivide_ml_kem_768_decaps.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    # Initialize library
    status = lib.rivide_init()
    if status != 0:
        print(f"Failed to initialize Rivide: error code {status}")
        return 1

    version = lib.rivide_version_string().decode("utf-8")
    print(f"Loaded Rivide C Library Version: {version}")

    # Perform ML-KEM-768 Key Encapsulation in Python
    pk = ctypes.create_string_buffer(RIVIDE_ML_KEM_768_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(RIVIDE_ML_KEM_768_SECRETKEYBYTES)
    ct = ctypes.create_string_buffer(RIVIDE_ML_KEM_768_CIPHERTEXTBYTES)
    ss_encap = ctypes.create_string_buffer(RIVIDE_ML_KEM_BYTES)
    ss_decap = ctypes.create_string_buffer(RIVIDE_ML_KEM_BYTES)

    print("[Python] Generating ML-KEM-768 keypair...")
    lib.rivide_ml_kem_768_keypair(pk, sk)

    print("[Python] Encapsulating shared secret...")
    lib.rivide_ml_kem_768_encaps(ct, ss_encap, pk)

    print("[Python] Decapsulating shared secret...")
    lib.rivide_ml_kem_768_decaps(ss_decap, ct, sk)

    if ss_encap.raw == ss_decap.raw:
        print(
            "[SUCCESS] Python ctypes integration established matching 256-bit PQC key!"
        )
        print(f"Key Hex: {ss_encap.raw.hex()[:32]}...")
    else:
        print("[FAILURE] Key mismatch in Python wrapper!")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
