<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Quick Start: C99 Integration

This guide demonstrates how to integrate, compile, and link **Rivide** into standard C and C++ applications.

## 1. Building and Installing Rivide

Clone the repository and compile static and shared library archives:

```bash
git clone https://github.com/mrvlous/rivide.git
cd rivide

# Build static library (librivide.a) and shared library (librivide.so)
make build

# Run automated tests to verify functionality
make test

# Install headers to /usr/local/include and libraries to /usr/local/lib
sudo make install
```

## 2. Minimal C Application: ML-KEM-768 Key Encapsulation

Create a new file named `main_kem.c`:

```c
#include <stdio.h>
#include <string.h>
#include <rivide/rivide.h>

int main(void) {
    /* 1. Initialize the cryptographic engine */
    if (rivide_init() != RIVIDE_SUCCESS) {
        fprintf(stderr, "Failed to initialize Rivide engine\n");
        return 1;
    }
    printf("Rivide Engine v%s initialized successfully.\n", rivide_version_string());

    /* 2. Allocate stack buffers */
    uint8_t pk[RIVIDE_ML_KEM_768_PUBLICKEYBYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SECRETKEYBYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CIPHERTEXTBYTES];
    uint8_t ss_alice[RIVIDE_ML_KEM_BYTES];
    uint8_t ss_bob[RIVIDE_ML_KEM_BYTES];

    /* 3. Alice generates keypair */
    printf("[Alice] Generating ML-KEM-768 keypair...\n");
    if (rivide_ml_kem_768_keygen(pk, sk) != RIVIDE_SUCCESS) return 1;

    /* 4. Bob encapsulates shared secret using Alice's public key */
    printf("[Bob] Encapsulating shared secret...\n");
    if (rivide_ml_kem_768_encaps(ct, ss_bob, pk) != RIVIDE_SUCCESS) return 1;

    /* 5. Alice decapsulates shared secret using her secret key */
    printf("[Alice] Decapsulating shared secret from ciphertext...\n");
    if (rivide_ml_kem_768_decaps(ss_alice, ct, sk) != RIVIDE_SUCCESS) return 1;

    /* 6. Verify shared secrets match in constant time */
    if (rivide_ct_memcmp(ss_alice, ss_bob, RIVIDE_ML_KEM_BYTES) == 0) {
        printf("[SUCCESS] 256-bit quantum-safe shared secret established!\n");
    } else {
        printf("[ERROR] Shared secret mismatch!\n");
        return 1;
    }

    /* 7. Zeroize secret memory buffers before exit */
    rivide_cleanse(sk, sizeof(sk));
    rivide_cleanse(ss_alice, sizeof(ss_alice));
    rivide_cleanse(ss_bob, sizeof(ss_bob));

    return 0;
}
```

## 3. Compiling the Application

### Direct GCC / Clang Command

```bash
# Using installed system library
gcc -std=c99 -O3 main_kem.c -lrivide -o main_kem

# Or linking against local build directory
gcc -std=c99 -O3 main_kem.c -I./include build/librivide.a -o main_kem
```

### Using CMake (`CMakeLists.txt`)

```cmake
cmake_minimum_required(VERSION 3.10)
project(my_pqc_app C)

set(CMAKE_C_STANDARD 99)

find_package(PkgConfig REQUIRED)
pkg_check_modules(RIVIDE REQUIRED rivide)

add_executable(my_pqc_app main_kem.c)
target_include_directories(my_pqc_app PRIVATE ${RIVIDE_INCLUDE_DIRS})
target_link_libraries(my_pqc_app PRIVATE ${RIVIDE_LIBRARIES})
```
