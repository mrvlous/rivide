<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide: Post-Quantum Cryptography C99 Library

[![Version](https://img.shields.io/badge/Version-v1.1.0-informational.svg)](CHANGELOG.md)
[![CI](https://github.com/mrvlous/rivide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml)
[![Linux](https://img.shields.io/badge/Linux-Ubuntu%20(GCC%20%7C%20Clang)-blue.svg?logo=ubuntu&logoColor=white)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![macOS](https://img.shields.io/badge/macOS-Apple%20Clang-black.svg?logo=apple&logoColor=white)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![Windows](https://img.shields.io/badge/Windows-MSVC-0078D6.svg?logo=windows&logoColor=white)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C Standard](https://img.shields.io/badge/C-C99-green.svg)](docs/architecture/overview.md)
[![Security](https://img.shields.io/badge/Security-Constant--Time-orange.svg)](docs/architecture/memory_random.md)
[![Memory](https://img.shields.io/badge/Memory-0%20Malloc-purple.svg)](docs/architecture/overview.md)

**Rivide** is a high-performance, zero-dependency, constant-time C99 Post-Quantum Cryptography (PQC) library. It implements the official **NIST FIPS 203** (ML-KEM) and **NIST FIPS 204** (ML-DSA) standards, engineered specifically for embedded systems, network security protocols, operating system kernels, and security-critical applications.

## Key Features

- **NIST Post-Quantum Standards**:
  - **ML-KEM (FIPS 203)**: Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
  - **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
- **ISO C99 Standard Compliance**: Written in clean, portable C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
- **Zero Dynamic Memory Allocation (0 Malloc)**: Never invokes `malloc` or heap allocation. All buffers are fixed-size and caller-allocated on the stack.
- **Constant-Time Side-Channel Protection**: Features constant-time comparisons (`rivide_ct_memcmp`) and conditional selections (`rivide_ct_select`) to prevent timing side-channel attacks.
- **Secure Memory Cleansing**: Prevents compiler dead-store elimination via volatile barriers (`rivide_cleanse`) to guarantee zeroization of sensitive private keys in RAM.
- **Multi-Platform OS CSPRNG Engine**: Queries kernel entropy sources natively (`getrandom` on Linux, `getentropy` on macOS/BSD, `BCryptGenRandom` on Windows).
- **Built-in Symmetric Primitives**: Autonomous implementations of **Keccak-f[1600]** (SHA3-256/512, SHAKE-128/256) and **AES-128/256-GCM** AEAD.
- **Node.js Native Bindings**: Zero-dependency, high-performance Node-API (N-API) bindings and npm package ([`rivide`](bindings/node/README.md)) with full TypeScript definitions.

## Table of Contents

1. [Installation & Quick Start](#installation--quick-start)
2. [Code Tutorials & Usage Examples](#code-tutorials--usage-examples)
3. [Node.js / JavaScript / TypeScript Bindings Quick Start](#nodejs--javascript--typescript-bindings-quick-start)
4. [Rust Native Bindings Quick Start](#rust-native-bindings-quick-start)
5. [Parameter & Specification Summary](#parameter--specification-summary)
6. [Master Makefile Command Automation](#master-makefile-command-automation)
7. [Documentation Map](#documentation-map)
8. [License & Maintainers](#license--maintainers)

## Installation & Quick Start

### 1. Prerequisites
Install build dependencies (GCC/Clang, CMake, Make):

```bash
# Ubuntu / Debian
sudo apt-get install -y build-essential cmake ctest clang-format clang-tidy

# Arch Linux / Manjaro
sudo pacman -S base-devel cmake clang

# macOS (Homebrew)
brew install cmake clang-format
```

On **Windows**, install [CMake](https://cmake.org/download/) and use the Visual Studio Developer Command Prompt.

### 2. Building from Source
Clone the repository and build using the master Makefile:

```bash
# Clone the repository
git clone https://github.com/mrvlous/rivide.git
cd rivide

# Compile static/shared libraries, test suite, KAT, and examples
make build

# Run automated unit test suite
make test

# Execute official NIST Known Answer Test (KAT) validation suite
make kat

# Execute demonstration applications
make run-examples

# Run performance benchmarks
make bench
```

### 3. Installing System-Wide
Install static library archives and header files to system locations (e.g. `/usr/local`):

```bash
sudo make install
```

## Code Tutorials & Usage Examples

Include the unified master header in your C application:
```c
#include "rivide/rivide.h"
```

### Tutorial 1: ML-KEM-768 Key Exchange

This example demonstrates post-quantum key exchange between Alice and Bob:

```c
#include <stdio.h>
#include "rivide/rivide.h"

int main(void) {
    rivide_status_t status;

    /* 1. Initialize Rivide cryptographic library */
    status = rivide_init();
    if (status != RIVIDE_SUCCESS) {
        fprintf(stderr, "Rivide initialization failed\n");
        return 1;
    }

    /* 2. Allocate fixed-size key buffers (Zero Heap Allocation) */
    uint8_t alice_pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t alice_sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ciphertext[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t bob_shared_secret[RIVIDE_ML_KEM_768_SS_BYTES];
    uint8_t alice_shared_secret[RIVIDE_ML_KEM_768_SS_BYTES];

    /* 3. [Alice] Generate ML-KEM-768 keypair */
    printf("[Alice] Generating ML-KEM-768 key pair...\n");
    status = rivide_ml_kem_768_keygen(alice_pk, alice_sk);
    if (status != RIVIDE_SUCCESS) return 1;

    /* 4. [Bob] Encapsulate shared secret under Alice's public key */
    printf("[Bob] Encapsulating shared secret...\n");
    status = rivide_ml_kem_768_encaps(ciphertext, bob_shared_secret, alice_pk);
    if (status != RIVIDE_SUCCESS) return 1;

    /* 5. [Alice] Decapsulate ciphertext using her secret key */
    printf("[Alice] Decapsulating shared secret...\n");
    status = rivide_ml_kem_768_decaps(alice_shared_secret, ciphertext, alice_sk);
    if (status != RIVIDE_SUCCESS) return 1;

    /* 6. Verify matching shared secret (32 bytes) */
    if (rivide_ct_memcmp(alice_shared_secret, bob_shared_secret, RIVIDE_ML_KEM_768_SS_BYTES) == 0) {
        printf("SUCCESS: Shared secrets match! Quantum-safe key exchange complete.\n");
    } else {
        printf("ERROR: Shared secret mismatch!\n");
        return 1;
    }

    /* 7. Securely cleanse private keys in RAM */
    rivide_cleanse(alice_sk, sizeof(alice_sk));
    return 0;
}
```

Compile with: `gcc -O3 main.c -lrivide -o kem_app`

### Tutorial 2: ML-DSA-65 Digital Signature

This example demonstrates signing and verifying messages using ML-DSA-65:

```c
#include <stdio.h>
#include <string.h>
#include "rivide/rivide.h"

int main(void) {
    rivide_status_t status;

    /* 1. Initialize library */
    rivide_init();

    /* 2. Allocate fixed-size key and signature buffers */
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t signature[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(signature);

    const char *message = "Post-Quantum signed payload using Rivide library.";
    size_t msglen = strlen(message);

    /* 3. Generate ML-DSA-65 keypair */
    printf("[Signer] Generating ML-DSA-65 key pair...\n");
    status = rivide_ml_dsa_65_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) return 1;

    /* 4. Sign message */
    printf("[Signer] Signing message...\n");
    status = rivide_ml_dsa_65_sign(signature, &siglen, (const uint8_t *)message, msglen, sk);
    if (status != RIVIDE_SUCCESS) return 1;

    /* 5. Verify signature */
    printf("[Verifier] Verifying signature...\n");
    status = rivide_ml_dsa_65_verify(signature, siglen, (const uint8_t *)message, msglen, pk);
    if (status == RIVIDE_SUCCESS) {
        printf("SUCCESS: Signature is VALID!\n");
    } else {
        printf("ERROR: Signature verification failed!\n");
        return 1;
    }

    /* 6. Securely wipe secret key */
    rivide_cleanse(sk, sizeof(sk));
    return 0;
}
```

Compile with: `gcc -O3 main.c -lrivide -o dsa_app`

## Node.js / JavaScript / TypeScript Bindings Quick Start

Rivide provides official native Node-API bindings for JavaScript and TypeScript developers via the [`rivide`](bindings/node/README.md) package:

```bash
# npm
npm install rivide

# pnpm
pnpm add rivide

# yarn
yarn add rivide
```

```javascript
import { mlKem768, mlDsa65, utils } from 'rivide';

// ML-KEM-768 Key Exchange
const alice = mlKem768.keypair();
const bob = mlKem768.encaps(alice.publicKey);
const sharedSecret = mlKem768.decaps(bob.ciphertext, alice.secretKey);

// ML-DSA-65 Digital Signature
const signer = mlDsa65.keypair();
const signature = mlDsa65.sign('Quantum-Safe Contract', signer.secretKey);
const isValid = mlDsa65.verify(signature, 'Quantum-Safe Contract', signer.publicKey);

// Secure RAM Cleanup
utils.cleanse(alice.secretKey);
utils.cleanse(signer.secretKey);
```

For full documentation and TypeScript usage, refer to the [Node.js Bindings Guide](bindings/node/README.md).

## Rust Native Bindings Quick Start

Rivide provides official idiomatic Rust bindings via the [`rivide`](bindings/rust/README.md) crate:

```bash
cargo add rivide
```

```rust
use rivide::kem::MlKem768;
use rivide::dsa::MlDsa65;

// ML-KEM-768 Key Exchange
let alice = MlKem768::keypair().expect("KeyGen failed");
let bob = MlKem768::encapsulate(&alice.public_key).expect("Encaps failed");
let shared_secret = MlKem768::decapsulate(&bob.ciphertext, &alice.secret_key).expect("Decaps failed");

assert_eq!(shared_secret, bob.shared_secret);

// ML-DSA-65 Digital Signature
let signer = MlDsa65::keypair().expect("KeyGen failed");
let signature = MlDsa65::sign(b"Quantum-Safe Transaction", &signer.secret_key).expect("Sign failed");
let is_valid = MlDsa65::verify(&signature, b"Quantum-Safe Transaction", &signer.public_key);

assert!(is_valid);
```

For full documentation, refer to the [Rust Bindings Guide](bindings/rust/README.md).

## Parameter & Specification Summary

| Algorithm | Standard | Public Key | Secret Key | Ciphertext / Signature | Shared Key / Security |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | NIST FIPS 203 | `1184` bytes | `2400` bytes | `1088` bytes | 32 bytes (Category 3 / AES-192) |
| **ML-KEM-1024** | NIST FIPS 203 | `1568` bytes | `3168` bytes | `1568` bytes | 32 bytes (Category 5 / AES-256) |
| **ML-DSA-65** | NIST FIPS 204 | `1952` bytes | `4032` bytes | `3309` bytes | Category 3 / AES-192 equivalent |
| **ML-DSA-87** | NIST FIPS 204 | `2592` bytes | `4896` bytes | `4627` bytes | Category 5 / AES-256 equivalent |

## Master Makefile Command Automation

The master [`Makefile`](Makefile) provides simple automation targets:

| Command | Action |
| :--- | :--- |
| `make build` | Compile static library `librivide.a`, shared library, tests, KAT, and examples |
| `make test` | Run automated unit test suite using CTest |
| `make kat` | Execute official NIST Known Answer Test (KAT) validation suite |
| `make bench` | Compile and execute dedicated PQC performance benchmark subsystem |
| `make run-examples` | Build and execute demonstration applications sequentially |
| `make fuzz CC=clang` | Compile LLVM libFuzzer fuzzing targets with AddressSanitizer |
| `make node-build` | Compile Node-API native bindings addon using `node-gyp` |
| `make node-test` | Run automated Node.js test suite across all PQC primitives |
| `make node-bench` | Execute Node.js performance benchmarking suite |
| `make format` | Auto-format all C/H files using `.clang-format` |
| `make check-format` | Verify code formatting against `.clang-format` rules |
| `make lint` | Run static code analysis using `clang-tidy` |
| `make check` | Check system environment for required dependencies |
| `make clean` | Delete build outputs and temporary artifacts |

## Documentation Map

For detailed architectural and API documentation, refer to the [`docs/`](docs/README.md) directory:

- [Documentation Map Index](docs/README.md)
- **Architecture Guides**:
  - [Library Architecture Overview](docs/architecture/overview.md)
  - [ML-KEM (FIPS 203) Architecture](docs/architecture/pqc_ml_kem.md)
  - [ML-DSA (FIPS 204) Architecture](docs/architecture/pqc_ml_dsa.md)
  - [Symmetric Primitives Architecture](docs/architecture/crypto_primitives.md)
  - [SIMD NTT Vectorization Engine](docs/architecture/pqc_simd_ntt.md)
  - [Memory & CSPRNG Engine Architecture](docs/architecture/memory_random.md)
  - [NIST KAT & Testing Subsystem](docs/architecture/testing_and_kat.md)
  - [Automated Fuzzing Subsystem](docs/architecture/fuzzing.md)
  - [Dedicated Benchmark Subsystem](docs/architecture/benchmarking.md)
  - [Node.js Native Bindings](docs/architecture/node_bindings.md)
- **API References**:
  - [Core API Reference](docs/api/core.md)
  - [ML-KEM API Reference](docs/api/ml_kem.md)
  - [ML-DSA API Reference](docs/api/ml_dsa.md)
  - [SIMD NTT API Reference](docs/api/ntt_simd.md)
  - [Symmetric Cryptography API Reference](docs/api/crypto_utils.md)
  - [Node.js (npm) API](bindings/node/README.md)
- **Real-World Integration Guides**:
  - [Web Development & API Security (Post-Quantum JWT)](docs/use_cases/web_jwt.md)
  - [Network Security & TLS (Hybrid KEM Exchange)](docs/use_cases/network_tls.md)
  - [Embedded Systems & Firmware (Secure Boot & OTA)](docs/use_cases/embedded_iot.md)
  - [Cloud Storage & Database (Envelope Encryption)](docs/use_cases/cloud_storage.md)
- **Contribution Guidelines**:
  - [Development Environment Setup](docs/contributing/setup.md)
  - [Building and Tooling](docs/contributing/build.md)
  - [Coding & License Style Guidelines](docs/contributing/style.md)

## License & Maintainers

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

- **Author & Maintainer**: Moh. Ananda Firmansyah Putra ([@mrvlous](https://github.com/mrvlous))
- **Maintainers Roster**: [MAINTAINERS](MAINTAINERS)
- **Contributors & Credits**: [CREDITS](CREDITS)
