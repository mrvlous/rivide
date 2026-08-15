// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

//! Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM, NIST FIPS 203).

use crate::error::RivideError;
use crate::sys::*;
use crate::utils::cleanse;

/// ML-KEM-768 Public Key (1184 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlKem768PublicKey([u8; RIVIDE_ML_KEM_768_PK_BYTES]);

impl MlKem768PublicKey {
    /// Creates a new public key from a fixed-size byte array.
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_KEM_768_PK_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns a slice reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_KEM_768_PK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlKem768PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem768PublicKey({} bytes)", self.0.len())
    }
}

/// ML-KEM-768 Secret Key (2400 bytes).
///
/// Automatically cleansed from memory using `rivide_cleanse` on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768SecretKey([u8; RIVIDE_ML_KEM_768_SK_BYTES]);

impl MlKem768SecretKey {
    /// Creates a new secret key from a fixed-size byte array.
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_KEM_768_SK_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns a slice reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_KEM_768_SK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKem768SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MlKem768SecretKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl std::fmt::Debug for MlKem768SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem768SecretKey([REDACTED])")
    }
}

/// ML-KEM-768 Keypair containing public and secret keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKem768KeyPair {
    pub public_key: MlKem768PublicKey,
    pub secret_key: MlKem768SecretKey,
}

/// ML-KEM-768 Encapsulation Result containing ciphertext and 32-byte shared secret.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768EncapsResult {
    pub ciphertext: [u8; RIVIDE_ML_KEM_768_CT_BYTES],
    pub shared_secret: [u8; RIVIDE_ML_KEM_768_SS_BYTES],
}

impl Drop for MlKem768EncapsResult {
    fn drop(&mut self) {
        cleanse(&mut self.shared_secret);
    }
}

impl std::fmt::Debug for MlKem768EncapsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlKem768EncapsResult {{ ciphertext: [{} bytes], shared_secret: [REDACTED] }}",
            self.ciphertext.len()
        )
    }
}

/// ML-KEM-768 Key Encapsulation Mechanism (NIST Security Category 3).
pub struct MlKem768;

impl MlKem768 {
    /// Generates a new post-quantum ML-KEM-768 keypair.
    pub fn keypair() -> Result<MlKem768KeyPair, RivideError> {
        let mut pk = [0u8; RIVIDE_ML_KEM_768_PK_BYTES];
        let mut sk = [0u8; RIVIDE_ML_KEM_768_SK_BYTES];

        let status = unsafe { rivide_ml_kem_768_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        RivideError::from_status(status).map(|_| MlKem768KeyPair {
            public_key: MlKem768PublicKey(pk),
            secret_key: MlKem768SecretKey(sk),
        })
    }

    /// Encapsulates a 32-byte shared secret under a recipient's public key.
    pub fn encapsulate(public_key: &MlKem768PublicKey) -> Result<MlKem768EncapsResult, RivideError> {
        let mut ct = [0u8; RIVIDE_ML_KEM_768_CT_BYTES];
        let mut ss = [0u8; RIVIDE_ML_KEM_768_SS_BYTES];

        let status = unsafe {
            rivide_ml_kem_768_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), public_key.0.as_ptr())
        };
        RivideError::from_status(status).map(|_| MlKem768EncapsResult {
            ciphertext: ct,
            shared_secret: ss,
        })
    }

    /// Decapsulates a 32-byte shared secret from a ciphertext using a secret key.
    pub fn decapsulate(
        ciphertext: &[u8; RIVIDE_ML_KEM_768_CT_BYTES],
        secret_key: &MlKem768SecretKey,
    ) -> Result<[u8; RIVIDE_ML_KEM_768_SS_BYTES], RivideError> {
        let mut ss = [0u8; RIVIDE_ML_KEM_768_SS_BYTES];

        let status = unsafe {
            rivide_ml_kem_768_decaps(ss.as_mut_ptr(), ciphertext.as_ptr(), secret_key.0.as_ptr())
        };
        RivideError::from_status(status).map(|_| ss)
    }
}

// ------------------------------------------------------------------------------------------------
// ML-KEM-1024
// ------------------------------------------------------------------------------------------------

/// ML-KEM-1024 Public Key (1568 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlKem1024PublicKey([u8; RIVIDE_ML_KEM_1024_PK_BYTES]);

impl MlKem1024PublicKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_KEM_1024_PK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_KEM_1024_PK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKem1024PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlKem1024PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem1024PublicKey({} bytes)", self.0.len())
    }
}

/// ML-KEM-1024 Secret Key (3168 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem1024SecretKey([u8; RIVIDE_ML_KEM_1024_SK_BYTES]);

impl MlKem1024SecretKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_KEM_1024_SK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_KEM_1024_SK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKem1024SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MlKem1024SecretKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl std::fmt::Debug for MlKem1024SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem1024SecretKey([REDACTED])")
    }
}

/// ML-KEM-1024 Keypair containing public and secret keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKem1024KeyPair {
    pub public_key: MlKem1024PublicKey,
    pub secret_key: MlKem1024SecretKey,
}

/// ML-KEM-1024 Encapsulation Result.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem1024EncapsResult {
    pub ciphertext: [u8; RIVIDE_ML_KEM_1024_CT_BYTES],
    pub shared_secret: [u8; RIVIDE_ML_KEM_1024_SS_BYTES],
}

impl Drop for MlKem1024EncapsResult {
    fn drop(&mut self) {
        cleanse(&mut self.shared_secret);
    }
}

impl std::fmt::Debug for MlKem1024EncapsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlKem1024EncapsResult {{ ciphertext: [{} bytes], shared_secret: [REDACTED] }}",
            self.ciphertext.len()
        )
    }
}

/// ML-KEM-1024 Key Encapsulation Mechanism (NIST Security Category 5).
pub struct MlKem1024;

impl MlKem1024 {
    /// Generates a new post-quantum ML-KEM-1024 keypair.
    pub fn keypair() -> Result<MlKem1024KeyPair, RivideError> {
        let mut pk = [0u8; RIVIDE_ML_KEM_1024_PK_BYTES];
        let mut sk = [0u8; RIVIDE_ML_KEM_1024_SK_BYTES];

        let status = unsafe { rivide_ml_kem_1024_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        RivideError::from_status(status).map(|_| MlKem1024KeyPair {
            public_key: MlKem1024PublicKey(pk),
            secret_key: MlKem1024SecretKey(sk),
        })
    }

    /// Encapsulates a 32-byte shared secret under an ML-KEM-1024 public key.
    pub fn encapsulate(public_key: &MlKem1024PublicKey) -> Result<MlKem1024EncapsResult, RivideError> {
        let mut ct = [0u8; RIVIDE_ML_KEM_1024_CT_BYTES];
        let mut ss = [0u8; RIVIDE_ML_KEM_1024_SS_BYTES];

        let status = unsafe {
            rivide_ml_kem_1024_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), public_key.0.as_ptr())
        };
        RivideError::from_status(status).map(|_| MlKem1024EncapsResult {
            ciphertext: ct,
            shared_secret: ss,
        })
    }

    /// Decapsulates a 32-byte shared secret from an ML-KEM-1024 ciphertext.
    pub fn decapsulate(
        ciphertext: &[u8; RIVIDE_ML_KEM_1024_CT_BYTES],
        secret_key: &MlKem1024SecretKey,
    ) -> Result<[u8; RIVIDE_ML_KEM_1024_SS_BYTES], RivideError> {
        let mut ss = [0u8; RIVIDE_ML_KEM_1024_SS_BYTES];

        let status = unsafe {
            rivide_ml_kem_1024_decaps(ss.as_mut_ptr(), ciphertext.as_ptr(), secret_key.0.as_ptr())
        };
        RivideError::from_status(status).map(|_| ss)
    }
}
