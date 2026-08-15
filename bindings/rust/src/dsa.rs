// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

//! Module-Lattice-Based Digital Signature Algorithm (ML-DSA, NIST FIPS 204).

use crate::error::RivideError;
use crate::sys::*;
use crate::utils::cleanse;

/// ML-DSA-65 Public Key (1952 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlDsa65PublicKey([u8; RIVIDE_ML_DSA_65_PK_BYTES]);

impl MlDsa65PublicKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_65_PK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_65_PK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlDsa65PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65PublicKey({} bytes)", self.0.len())
    }
}

/// ML-DSA-65 Secret Key (4032 bytes).
///
/// Automatically cleansed from memory on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65SecretKey([u8; RIVIDE_ML_DSA_65_SK_BYTES]);

impl MlDsa65SecretKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_65_SK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_65_SK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa65SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MlDsa65SecretKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl std::fmt::Debug for MlDsa65SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65SecretKey([REDACTED])")
    }
}

/// ML-DSA-65 Keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65KeyPair {
    pub public_key: MlDsa65PublicKey,
    pub secret_key: MlDsa65SecretKey,
}

/// ML-DSA-65 Signature (3309 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlDsa65Signature([u8; RIVIDE_ML_DSA_65_SIG_BYTES]);

impl MlDsa65Signature {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_65_SIG_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_65_SIG_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65Signature({} bytes)", self.0.len())
    }
}

/// ML-DSA-65 Digital Signature Algorithm (NIST Security Category 3).
pub struct MlDsa65;

impl MlDsa65 {
    /// Generates a new post-quantum ML-DSA-65 signing keypair.
    pub fn keypair() -> Result<MlDsa65KeyPair, RivideError> {
        let mut pk = [0u8; RIVIDE_ML_DSA_65_PK_BYTES];
        let mut sk = [0u8; RIVIDE_ML_DSA_65_SK_BYTES];

        let status = unsafe { rivide_ml_dsa_65_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        RivideError::from_status(status).map(|_| MlDsa65KeyPair {
            public_key: MlDsa65PublicKey(pk),
            secret_key: MlDsa65SecretKey(sk),
        })
    }

    /// Signs an arbitrary message payload with an ML-DSA-65 secret key.
    pub fn sign(message: &[u8], secret_key: &MlDsa65SecretKey) -> Result<MlDsa65Signature, RivideError> {
        let mut sig = [0u8; RIVIDE_ML_DSA_65_SIG_BYTES];
        let mut siglen: usize = 0;

        let status = unsafe {
            rivide_ml_dsa_65_sign(
                sig.as_mut_ptr(),
                &mut siglen,
                message.as_ptr(),
                message.len(),
                secret_key.0.as_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| MlDsa65Signature(sig))
    }

    /// Verifies an ML-DSA-65 digital signature against a message and public key.
    pub fn verify(
        signature: &MlDsa65Signature,
        message: &[u8],
        public_key: &MlDsa65PublicKey,
    ) -> bool {
        let status = unsafe {
            rivide_ml_dsa_65_verify(
                signature.0.as_ptr(),
                signature.0.len(),
                message.as_ptr(),
                message.len(),
                public_key.0.as_ptr(),
            )
        };
        status == RIVIDE_SUCCESS
    }
}

// ------------------------------------------------------------------------------------------------
// ML-DSA-87
// ------------------------------------------------------------------------------------------------

/// ML-DSA-87 Public Key (2592 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlDsa87PublicKey([u8; RIVIDE_ML_DSA_87_PK_BYTES]);

impl MlDsa87PublicKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_87_PK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_87_PK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa87PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlDsa87PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa87PublicKey({} bytes)", self.0.len())
    }
}

/// ML-DSA-87 Secret Key (4896 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa87SecretKey([u8; RIVIDE_ML_DSA_87_SK_BYTES]);

impl MlDsa87SecretKey {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_87_SK_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_87_SK_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa87SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for MlDsa87SecretKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl std::fmt::Debug for MlDsa87SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa87SecretKey([REDACTED])")
    }
}

/// ML-DSA-87 Keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa87KeyPair {
    pub public_key: MlDsa87PublicKey,
    pub secret_key: MlDsa87SecretKey,
}

/// ML-DSA-87 Signature (4627 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlDsa87Signature([u8; RIVIDE_ML_DSA_87_SIG_BYTES]);

impl MlDsa87Signature {
    pub const fn from_bytes(bytes: [u8; RIVIDE_ML_DSA_87_SIG_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RIVIDE_ML_DSA_87_SIG_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa87Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlDsa87Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa87Signature({} bytes)", self.0.len())
    }
}

/// ML-DSA-87 Digital Signature Algorithm (NIST Security Category 5).
pub struct MlDsa87;

impl MlDsa87 {
    /// Generates a new post-quantum ML-DSA-87 signing keypair.
    pub fn keypair() -> Result<MlDsa87KeyPair, RivideError> {
        let mut pk = [0u8; RIVIDE_ML_DSA_87_PK_BYTES];
        let mut sk = [0u8; RIVIDE_ML_DSA_87_SK_BYTES];

        let status = unsafe { rivide_ml_dsa_87_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        RivideError::from_status(status).map(|_| MlDsa87KeyPair {
            public_key: MlDsa87PublicKey(pk),
            secret_key: MlDsa87SecretKey(sk),
        })
    }

    /// Signs an arbitrary message payload with an ML-DSA-87 secret key.
    pub fn sign(message: &[u8], secret_key: &MlDsa87SecretKey) -> Result<MlDsa87Signature, RivideError> {
        let mut sig = [0u8; RIVIDE_ML_DSA_87_SIG_BYTES];
        let mut siglen: usize = 0;

        let status = unsafe {
            rivide_ml_dsa_87_sign(
                sig.as_mut_ptr(),
                &mut siglen,
                message.as_ptr(),
                message.len(),
                secret_key.0.as_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| MlDsa87Signature(sig))
    }

    /// Verifies an ML-DSA-87 digital signature against a message and public key.
    pub fn verify(
        signature: &MlDsa87Signature,
        message: &[u8],
        public_key: &MlDsa87PublicKey,
    ) -> bool {
        let status = unsafe {
            rivide_ml_dsa_87_verify(
                signature.0.as_ptr(),
                signature.0.len(),
                message.as_ptr(),
                message.len(),
                public_key.0.as_ptr(),
            )
        };
        status == RIVIDE_SUCCESS
    }
}
