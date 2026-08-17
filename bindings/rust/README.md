<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Rivide: Post-Quantum Cryptography Rust Crate

[![Crates.io](https://img.shields.io/crates/v/rivide.svg)](https://crates.io/crates/rivide)
[![Documentation](https://docs.rs/rivide/badge.svg)](https://docs.rs/rivide)
[![CI](https://github.com/mrvlous/rivide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/mrvlous/rivide/actions/workflows/codeql.yml)
[![Rust](https://img.shields.io/badge/Rust-%3E%3D1.70.0-brightgreen.svg?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C Engine](https://img.shields.io/badge/Engine-C99%20SIMD-green.svg)](https://github.com/mrvlous/rivide)
[![Security](https://img.shields.io/badge/Security-Constant--Time-orange.svg)](docs/api.md)
[![Memory](https://img.shields.io/badge/Memory-RAII%20Zeroize-purple.svg)](docs/api.md)

**Rivide** for Rust (`rivide`) provides high-performance, zero-allocation, idiomatic Rust bindings for the Rivide Post-Quantum Cryptography (PQC) C99 library. It implements finalized **NIST FIPS 203** (ML-KEM) and **NIST FIPS 204** (ML-DSA) standards with automated RAII memory zeroization, constant-time arithmetic, and native AVX2 / ARM NEON hardware acceleration.

## Key Features

- **Official NIST Post-Quantum Standards**:
  - **ML-KEM (FIPS 203)**: Module-Lattice-Based Key Encapsulation Mechanism (**ML-KEM-768** and **ML-KEM-1024**).
  - **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm (**ML-DSA-65** and **ML-DSA-87**).
- **Zero-Setup C99 Compilation**: `build.rs` compiles the underlying C99 engine directly using the `cc` build dependency. No external pre-installed C libraries or system packages are required.
- **Zero Heap Allocations (0 Malloc)**: Pure stack-allocated byte arrays (`[u8; N]`) for core cryptographic keys, ciphertexts, and signatures.
- **Automated RAII Memory Safety**: Secret keys (`MlKem768SecretKey`, `MlDsa65SecretKey`, etc.) implement the `Drop` trait and automatically invoke `rivide_cleanse` upon exiting scope.
- **Hardware SIMD Vector Acceleration**: Executes native AVX2 (256-bit) and ARM NEON (128-bit) vectorized polynomial arithmetic directly in C.
- **Constant-Time Side-Channel Protection**: Built-in constant-time byte comparisons (`utils::ct_memcmp`) and rejection sampling.
- **Integrated Symmetric Primitives**: Native implementations of **SHA3-256/512**, **SHAKE-128/256**, and **AES-128/256-GCM** AEAD.

## Table of Contents

1. [Installation & Quick Start](#installation--quick-start)
2. [Code Tutorials & Usage Examples](#code-tutorials--usage-examples)
   - [Tutorial 1: ML-KEM-768 Quantum-Safe Key Exchange](#tutorial-1-ml-kem-768-quantum-safe-key-exchange)
   - [Tutorial 2: ML-DSA-65 Digital Signature & Verification](#tutorial-2-ml-dsa-65-digital-signature--verification)
   - [Tutorial 3: Hybrid PQC + AES-256-GCM Secure Channel](#tutorial-3-hybrid-pqc--aes-256-gcm-secure-channel)
3. [Parameter & Specification Summary](#parameter--specification-summary)
4. [Cargo Automation & Testing](#cargo-automation--testing)
5. [API Reference & Namespaces](#api-reference--namespaces)
6. [Documentation Map](#documentation-map)
7. [License & Maintainers](#license--maintainers)

## Installation & Quick Start

### 1. Installation

Add `rivide` to your project using `cargo add`:

```bash
cargo add rivide
```

Or add it directly to your `Cargo.toml`:

```toml
[dependencies]
rivide = "1.1.3"
```

### 2. Building from Source

Clone the repository and compile using Cargo:

```bash
# Clone the repository
git clone https://github.com/mrvlous/rivide.git
cd rivide/bindings/rust

# Build optimized release artifact
cargo build --release

# Run automated integration test suite
cargo test

# Run executable demonstration examples
cargo run --example kem_exchange
cargo run --example dsa_sign
cargo run --example hybrid_channel
```

## Code Tutorials & Usage Examples

### Tutorial 1: ML-KEM-768 Quantum-Safe Key Exchange

Exchange a 256-bit symmetric session key between Alice and Bob using NIST FIPS 203 ML-KEM-768 (Security Category 3):

```rust
use rivide::kem::MlKem768;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Alice generates ML-KEM-768 keypair
    let alice = MlKem768::keypair()?;
    println!("Alice Public Key Length: {} bytes", alice.public_key.as_bytes().len());

    // 2. Bob encapsulates a 32-byte shared secret under Alice's public key
    let bob = MlKem768::encapsulate(&alice.public_key)?;
    println!("Bob Ciphertext Length   : {} bytes", bob.ciphertext.len());

    // 3. Alice decapsulates the shared secret using her secret key
    let alice_ss = MlKem768::decapsulate(&bob.ciphertext, &alice.secret_key)?;

    // 4. Verify shared secrets match in constant time
    assert_eq!(alice_ss, bob.shared_secret);
    println!("Quantum-safe shared secret established successfully!");

    // Secret keys automatically zeroized upon drop
    Ok(())
}
```

### Tutorial 2: ML-DSA-65 Digital Signature & Verification

Sign and verify arbitrary documents and tokens using NIST FIPS 204 ML-DSA-65 (Security Category 3):

```rust
use rivide::dsa::MlDsa65;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Signer generates ML-DSA-65 keypair
    let signer = MlDsa65::keypair()?;

    // 2. Sign arbitrary message payload
    let document = b"Quantum-Safe Financial Authorization Payload: Transfer $50,000 to Alice.";
    let signature = MlDsa65::sign(document, &signer.secret_key)?;
    println!("Signature Length: {} bytes", signature.as_bytes().len());

    // 3. Verifier validates signature against public key
    let is_valid = MlDsa65::verify(&signature, document, &signer.public_key);
    assert!(is_valid);
    println!("Signature is 100% authentic and valid!");

    // 4. Test tamper detection
    let tampered_doc = b"Quantum-Safe Financial Authorization Payload: Transfer $500,000 to Alice.";
    let is_tampered_valid = MlDsa65::verify(&signature, tampered_doc, &signer.public_key);
    assert!(!is_tampered_valid);
    println!("Tampered payload successfully rejected!");

    Ok(())
}
```

### Tutorial 3: Hybrid PQC + AES-256-GCM Secure Channel

Combine ML-KEM-768 with AES-256-GCM AEAD to build a post-quantum confidential authenticated transport channel:

```rust
use rivide::crypto::AesGcm;
use rivide::kem::MlKem768;
use rivide::utils::randombytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Server generates ephemeral ML-KEM-768 keypair
    let server = MlKem768::keypair()?;

    // 2. Client encapsulates session key under server public key
    let kem = MlKem768::encapsulate(&server.public_key)?;
    let session_key = kem.shared_secret; // 32-byte PQC key

    // 3. Client encrypts payload using AES-256-GCM
    let payload = b"CONFIDENTIAL: Sovereign post-quantum financial wire instructions.";
    let iv_bytes = randombytes(12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    let aad = b"Protocol:TLS1.3-PQC-Hybrid";

    let encrypted = AesGcm::encrypt_256(&session_key, &iv, payload, Some(aad))?;

    // 4. Server decapsulates session key and decrypts payload
    let server_key = MlKem768::decapsulate(&kem.ciphertext, &server.secret_key)?;
    let decrypted = AesGcm::decrypt_256(&server_key, &iv, &encrypted.ciphertext, &encrypted.tag, Some(aad))?;

    assert_eq!(&decrypted, payload);
    println!("Hybrid channel decrypted successfully: \"{}\"", std::str::from_utf8(&decrypted)?);
    Ok(())
}
```

## Parameter & Specification Summary

| Primitive | Standard | Public Key | Secret Key | Ciphertext / Signature | Shared Key / Security |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | NIST FIPS 203 | `1184` bytes | `2400` bytes | `1088` bytes | 32 bytes (Category 3 / AES-192) |
| **ML-KEM-1024** | NIST FIPS 203 | `1568` bytes | `3168` bytes | `1568` bytes | 32 bytes (Category 5 / AES-256) |
| **ML-DSA-65** | NIST FIPS 204 | `1952` bytes | `4032` bytes | `3309` bytes | Category 3 / AES-192 equivalent |
| **ML-DSA-87** | NIST FIPS 204 | `2592` bytes | `4896` bytes | `4627` bytes | Category 5 / AES-256 equivalent |

## Cargo Automation & Testing

| Command | Purpose |
| :--- | :--- |
| `cargo build --release` | Compile optimized release static archive and binaries |
| `cargo test` | Run entire integration test suite and doc-tests |
| `cargo bench` | Execute high-precision performance benchmark harness |
| `cargo run --example kem_exchange` | Execute ML-KEM-768 key encapsulation tutorial |
| `cargo run --example dsa_sign` | Execute ML-DSA-65 digital signature tutorial |
| `cargo run --example hybrid_channel` | Execute hybrid PQC + AES-256-GCM secure channel tutorial |

## API Reference & Namespaces

- [`rivide::kem`](docs/api.md#key-encapsulation-mechanism-rividekem): ML-KEM-768 and ML-KEM-1024 types and routines.
- [`rivide::dsa`](docs/api.md#digital-signature-algorithm-rividedsa): ML-DSA-65 and ML-DSA-87 types and routines.
- [`rivide::crypto`](docs/api.md#symmetric-primitives-rividecrypto): SHA-3, SHAKE, and AES-GCM AEAD functions.
- [`rivide::utils`](docs/api.md#utilities--memory-safety-rivideutils): Memory cleansing, CSPRNG, and constant-time helpers.
- [`rivide::error`](docs/api.md#error-handling): Strongly typed error handling.

For complete documentation, see the [Rivide Rust API Reference](docs/api.md).

## Documentation Map

- [Rust API Reference](docs/api.md): Complete types, methods, and traits.
- [Rust Performance Benchmark Guide](docs/benchmarks.md): Benchmark methodology, parameters, and profiling metrics.
- [Rust Bindings Architecture Spec](../../docs/architecture/rust_bindings.md): Technical subsystem architecture.
- [Core Library Documentation](../../docs/README.md): Master documentation portal.
- [Main C99 Repository](https://github.com/mrvlous/rivide): Root C source code and NIST KAT test vectors.

## License & Maintainers

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

- **Author & Maintainer**: Moh. Ananda Firmansyah Putra ([@mrvlous](https://github.com/mrvlous))
- **Maintainers Roster**: [MAINTAINERS](https://github.com/mrvlous/rivide/blob/main/MAINTAINERS)
- **Contributors & Credits**: [CREDITS](https://github.com/mrvlous/rivide/blob/main/CREDITS)
