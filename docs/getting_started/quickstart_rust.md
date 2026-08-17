<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Quick Start: Rust Integration

This guide details how to add and use the official **`rivide`** crate in Rust applications.

## 1. Adding Dependency

Add `rivide` to your `Cargo.toml`:

```toml
[dependencies]
rivide = "1.1.3"
```

Or via `cargo add`:

```bash
cargo add rivide
```

## 2. Idiomatic Rust Example: Hybrid PQC Channel

Create `src/main.rs`:

```rust
use rivide::crypto::AesGcm;
use rivide::kem::MlKem768;
use rivide::utils::randombytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Server generates ephemeral ML-KEM-768 keypair
    let server = MlKem768::keypair()?;

    // 2. Client encapsulates 32-byte session key under server's public key
    let kem = MlKem768::encapsulate(&server.public_key)?;
    let session_key = kem.shared_secret;

    // 3. Client encrypts payload with AES-256-GCM
    let payload = b"SOVEREIGN: Quantum-safe confidential database transfer.";
    let iv_bytes = randombytes(12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    let aad = b"Context:SecureChannel-v1";

    let encrypted = AesGcm::encrypt_256(&session_key, &iv, payload, Some(aad))?;

    // 4. Server decapsulates session key and decrypts ciphertext
    let server_key = MlKem768::decapsulate(&kem.ciphertext, &server.secret_key)?;
    let decrypted = AesGcm::decrypt_256(&server_key, &iv, &encrypted.ciphertext, &encrypted.tag, Some(aad))?;

    assert_eq!(&decrypted, payload);
    println!("Decrypted Payload: \"{}\"", std::str::from_utf8(&decrypted)?);

    // Secret keys automatically zeroized on drop
    Ok(())
}
```

## 3. Running the Project

```bash
cargo run --release
```
