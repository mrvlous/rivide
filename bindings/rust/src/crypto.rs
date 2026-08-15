// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

//! Symmetric cryptographic primitives (SHA-3, SHAKE, AES-GCM AEAD).

use crate::error::RivideError;
use crate::sys::*;

/// SHA-3 Hash Functions (NIST FIPS 202).
pub struct Sha3;

impl Sha3 {
    /// Computes the 256-bit SHA3 digest of the input data.
    pub fn sha3_256(data: &[u8]) -> [u8; RIVIDE_SHA3_256_DIGEST_LENGTH] {
        let mut out = [0u8; RIVIDE_SHA3_256_DIGEST_LENGTH];
        unsafe {
            rivide_sha3_256(out.as_mut_ptr(), data.as_ptr(), data.len());
        }
        out
    }

    /// Computes the 512-bit SHA3 digest of the input data.
    pub fn sha3_512(data: &[u8]) -> [u8; RIVIDE_SHA3_512_DIGEST_LENGTH] {
        let mut out = [0u8; RIVIDE_SHA3_512_DIGEST_LENGTH];
        unsafe {
            rivide_sha3_512(out.as_mut_ptr(), data.as_ptr(), data.len());
        }
        out
    }

    /// Computes SHAKE-128 extendable-output hash of arbitrary output length.
    pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; output_len];
        unsafe {
            rivide_shake128(out.as_mut_ptr(), output_len, data.as_ptr(), data.len());
        }
        out
    }

    /// Computes SHAKE-256 extendable-output hash of arbitrary output length.
    pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; output_len];
        unsafe {
            rivide_shake256(out.as_mut_ptr(), output_len, data.as_ptr(), data.len());
        }
        out
    }
}

/// AES-GCM Authenticated Encryption with Associated Data (AEAD, NIST SP 800-38D).
pub struct AesGcm;

/// AES-GCM Encryption Result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AesGcmResult {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; RIVIDE_AES_GCM_TAG_BYTES],
}

impl AesGcm {
    /// Encrypts plaintext using AES-128-GCM (16-byte key, 12-byte IV).
    pub fn encrypt_128(
        key: &[u8; 16],
        iv: &[u8; RIVIDE_AES_GCM_IV_BYTES],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<AesGcmResult, RivideError> {
        let mut key_ctx = rivide_aes_key_t::default();
        let status = unsafe { rivide_aes128_key_expand(&mut key_ctx, key.as_ptr()) };
        RivideError::from_status(status)?;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; RIVIDE_AES_GCM_TAG_BYTES];

        let aad_ptr = aad.map(|a| a.as_ptr()).unwrap_or(std::ptr::null());
        let aad_len = aad.map(|a| a.len()).unwrap_or(0);

        let status = unsafe {
            rivide_aes_gcm_encrypt(
                &key_ctx,
                iv.as_ptr(),
                aad_ptr,
                aad_len,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| AesGcmResult { ciphertext, tag })
    }

    /// Authenticates and decrypts ciphertext using AES-128-GCM.
    pub fn decrypt_128(
        key: &[u8; 16],
        iv: &[u8; RIVIDE_AES_GCM_IV_BYTES],
        ciphertext: &[u8],
        tag: &[u8; RIVIDE_AES_GCM_TAG_BYTES],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, RivideError> {
        let mut key_ctx = rivide_aes_key_t::default();
        let status = unsafe { rivide_aes128_key_expand(&mut key_ctx, key.as_ptr()) };
        RivideError::from_status(status)?;

        let mut plaintext = vec![0u8; ciphertext.len()];

        let aad_ptr = aad.map(|a| a.as_ptr()).unwrap_or(std::ptr::null());
        let aad_len = aad.map(|a| a.len()).unwrap_or(0);

        let status = unsafe {
            rivide_aes_gcm_decrypt(
                &key_ctx,
                iv.as_ptr(),
                aad_ptr,
                aad_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| plaintext)
    }

    /// Encrypts plaintext using AES-256-GCM (32-byte key, 12-byte IV).
    pub fn encrypt_256(
        key: &[u8; 32],
        iv: &[u8; RIVIDE_AES_GCM_IV_BYTES],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<AesGcmResult, RivideError> {
        let mut key_ctx = rivide_aes_key_t::default();
        let status = unsafe { rivide_aes256_key_expand(&mut key_ctx, key.as_ptr()) };
        RivideError::from_status(status)?;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; RIVIDE_AES_GCM_TAG_BYTES];

        let aad_ptr = aad.map(|a| a.as_ptr()).unwrap_or(std::ptr::null());
        let aad_len = aad.map(|a| a.len()).unwrap_or(0);

        let status = unsafe {
            rivide_aes_gcm_encrypt(
                &key_ctx,
                iv.as_ptr(),
                aad_ptr,
                aad_len,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| AesGcmResult { ciphertext, tag })
    }

    /// Authenticates and decrypts ciphertext using AES-256-GCM.
    pub fn decrypt_256(
        key: &[u8; 32],
        iv: &[u8; RIVIDE_AES_GCM_IV_BYTES],
        ciphertext: &[u8],
        tag: &[u8; RIVIDE_AES_GCM_TAG_BYTES],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, RivideError> {
        let mut key_ctx = rivide_aes_key_t::default();
        let status = unsafe { rivide_aes256_key_expand(&mut key_ctx, key.as_ptr()) };
        RivideError::from_status(status)?;

        let mut plaintext = vec![0u8; ciphertext.len()];

        let aad_ptr = aad.map(|a| a.as_ptr()).unwrap_or(std::ptr::null());
        let aad_len = aad.map(|a| a.len()).unwrap_or(0);

        let status = unsafe {
            rivide_aes_gcm_decrypt(
                &key_ctx,
                iv.as_ptr(),
                aad_ptr,
                aad_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        };
        RivideError::from_status(status).map(|_| plaintext)
    }
}
