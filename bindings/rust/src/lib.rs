// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

//! # Rivide: Post-Quantum Cryptography Rust Crate
//!
//! Official high-performance, zero-allocation, idiomatic Rust bindings for the **Rivide**
//! Post-Quantum Cryptography (PQC) C99 library. Implements official **NIST FIPS 203** (ML-KEM)
//! and **NIST FIPS 204** (ML-DSA) standards with automated RAII memory zeroization.
//!
//! ## Key Modules
//!
//! - [`kem`]: Key Encapsulation Mechanisms (**ML-KEM-768** and **ML-KEM-1024**).
//! - [`dsa`]: Digital Signature Algorithms (**ML-DSA-65** and **ML-DSA-87**).
//! - [`crypto`]: Symmetric cryptography primitives (**SHA-3**, **SHAKE**, **AES-GCM** AEAD).
//! - [`utils`]: Memory cleansing, entropy generation, constant-time comparisons, and SIMD CPU queries.
//!
//! ## Quick Start
//!
//! ### ML-KEM-768 Key Encapsulation (FIPS 203)
//!
//! ```rust
//! use rivide::kem::MlKem768;
//!
//! // 1. Alice generates ML-KEM-768 keypair
//! let alice = MlKem768::keypair().expect("KeyGen failed");
//!
//! // 2. Bob encapsulates shared secret using Alice's public key
//! let bob = MlKem768::encapsulate(&alice.public_key).expect("Encaps failed");
//!
//! // 3. Alice decapsulates shared secret
//! let shared_secret = MlKem768::decapsulate(&bob.ciphertext, &alice.secret_key)
//!     .expect("Decaps failed");
//!
//! assert_eq!(shared_secret, bob.shared_secret);
//! ```
//!
//! ### ML-DSA-65 Digital Signatures (FIPS 204)
//!
//! ```rust
//! use rivide::dsa::MlDsa65;
//!
//! // 1. Generate signing keypair
//! let signer = MlDsa65::keypair().expect("KeyGen failed");
//!
//! // 2. Sign arbitrary message payload
//! let message = b"Quantum-Safe Signed Transaction Payload";
//! let signature = MlDsa65::sign(message, &signer.secret_key).expect("Sign failed");
//!
//! // 3. Verify signature authenticity
//! let is_valid = MlDsa65::verify(&signature, message, &signer.public_key);
//! assert!(is_valid);
//! ```

pub mod crypto;
pub mod dsa;
pub mod error;
pub mod kem;
pub mod sys;
pub mod utils;

// Re-exports for ergonomics
pub use crypto::{AesGcm, AesGcmResult, Sha3};
pub use dsa::{
    MlDsa65, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MlDsa87,
    MlDsa87KeyPair, MlDsa87PublicKey, MlDsa87SecretKey, MlDsa87Signature,
};
pub use error::RivideError;
pub use kem::{
    MlKem1024, MlKem1024EncapsResult, MlKem1024KeyPair, MlKem1024PublicKey, MlKem1024SecretKey,
    MlKem768, MlKem768EncapsResult, MlKem768KeyPair, MlKem768PublicKey, MlKem768SecretKey,
};
pub use utils::{
    cleanse, ct_memcmp, get_cpu_features, randombytes, randombytes_into, version, CpuFeatures,
};

/// Initializes the underlying Rivide C library subsystem.
///
/// Note: Initialization is called automatically upon first use, but can be invoked explicitly.
///
/// # Errors
/// Returns [`RivideError::InternalError`] if hardware or internal state initialization fails.
pub fn init() -> Result<(), RivideError> {
    let status = unsafe { sys::rivide_init() };
    RivideError::from_status(status)
}
