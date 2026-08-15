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

//! Raw low-level `extern "C"` FFI bindings to the Rivide C99 cryptographic library.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

pub type rivide_status_t = i32;

/// Operation completed successfully.
pub const RIVIDE_SUCCESS: rivide_status_t = 0;
/// Invalid parameter or null pointer passed to function.
pub const RIVIDE_ERR_INVALID_PARAM: rivide_status_t = -1;
/// Cryptographic signature or authentication tag verification failed.
pub const RIVIDE_ERR_VERIFICATION_FAILED: rivide_status_t = -2;
/// Operating system CSPRNG failure.
pub const RIVIDE_ERR_ENTROPY_FAILURE: rivide_status_t = -3;
/// Internal cryptographic or system fault.
pub const RIVIDE_ERR_INTERNAL: rivide_status_t = -4;

// Buffer length constants for ML-KEM
pub const RIVIDE_ML_KEM_768_PK_BYTES: usize = 1184;
pub const RIVIDE_ML_KEM_768_SK_BYTES: usize = 2400;
pub const RIVIDE_ML_KEM_768_CT_BYTES: usize = 1088;
pub const RIVIDE_ML_KEM_768_SS_BYTES: usize = 32;

pub const RIVIDE_ML_KEM_1024_PK_BYTES: usize = 1568;
pub const RIVIDE_ML_KEM_1024_SK_BYTES: usize = 3168;
pub const RIVIDE_ML_KEM_1024_CT_BYTES: usize = 1568;
pub const RIVIDE_ML_KEM_1024_SS_BYTES: usize = 32;

// Buffer length constants for ML-DSA
pub const RIVIDE_ML_DSA_65_PK_BYTES: usize = 1952;
pub const RIVIDE_ML_DSA_65_SK_BYTES: usize = 4032;
pub const RIVIDE_ML_DSA_65_SIG_BYTES: usize = 3309;

pub const RIVIDE_ML_DSA_87_PK_BYTES: usize = 2592;
pub const RIVIDE_ML_DSA_87_SK_BYTES: usize = 4896;
pub const RIVIDE_ML_DSA_87_SIG_BYTES: usize = 4627;

// Symmetric buffer length constants
pub const RIVIDE_SHA3_256_DIGEST_LENGTH: usize = 32;
pub const RIVIDE_SHA3_512_DIGEST_LENGTH: usize = 64;

pub const RIVIDE_AES_GCM_IV_BYTES: usize = 12;
pub const RIVIDE_AES_GCM_TAG_BYTES: usize = 16;

// CPU feature bitmask constants
pub const RIVIDE_CPU_AESNI: u32 = 1 << 0;
pub const RIVIDE_CPU_ARM_CE: u32 = 1 << 1;
pub const RIVIDE_CPU_AVX2: u32 = 1 << 2;
pub const RIVIDE_CPU_ARM_NEON: u32 = 1 << 3;

/// Expanded AES key schedule structure matching C `rivide_aes_key_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct rivide_aes_key_t {
    pub round_keys: [u32; 64],
    pub rounds: std::os::raw::c_int,
}

impl Default for rivide_aes_key_t {
    fn default() -> Self {
        Self {
            round_keys: [0u32; 64],
            rounds: 0,
        }
    }
}

extern "C" {
    // Core initialization
    pub fn rivide_init() -> rivide_status_t;
    pub fn rivide_version_string() -> *const std::os::raw::c_char;
    pub fn rivide_get_cpu_features() -> u32;

    // Memory and random
    pub fn rivide_cleanse(ptr: *mut std::os::raw::c_void, len: usize);
    pub fn rivide_randombytes(buf: *mut u8, len: usize) -> rivide_status_t;
    pub fn rivide_ct_memcmp(a: *const std::os::raw::c_void, b: *const std::os::raw::c_void, len: usize) -> i32;

    // ML-KEM-768
    pub fn rivide_ml_kem_768_keygen(pk: *mut u8, sk: *mut u8) -> rivide_status_t;
    pub fn rivide_ml_kem_768_encaps(ct: *mut u8, ss: *mut u8, pk: *const u8) -> rivide_status_t;
    pub fn rivide_ml_kem_768_decaps(ss: *mut u8, ct: *const u8, sk: *const u8) -> rivide_status_t;

    // ML-KEM-1024
    pub fn rivide_ml_kem_1024_keygen(pk: *mut u8, sk: *mut u8) -> rivide_status_t;
    pub fn rivide_ml_kem_1024_encaps(ct: *mut u8, ss: *mut u8, pk: *const u8) -> rivide_status_t;
    pub fn rivide_ml_kem_1024_decaps(ss: *mut u8, ct: *const u8, sk: *const u8) -> rivide_status_t;

    // ML-DSA-65
    pub fn rivide_ml_dsa_65_keygen(pk: *mut u8, sk: *mut u8) -> rivide_status_t;
    pub fn rivide_ml_dsa_65_sign(sig: *mut u8, siglen: *mut usize, msg: *const u8, msglen: usize, sk: *const u8) -> rivide_status_t;
    pub fn rivide_ml_dsa_65_verify(sig: *const u8, siglen: usize, msg: *const u8, msglen: usize, pk: *const u8) -> rivide_status_t;

    // ML-DSA-87
    pub fn rivide_ml_dsa_87_keygen(pk: *mut u8, sk: *mut u8) -> rivide_status_t;
    pub fn rivide_ml_dsa_87_sign(sig: *mut u8, siglen: *mut usize, msg: *const u8, msglen: usize, sk: *const u8) -> rivide_status_t;
    pub fn rivide_ml_dsa_87_verify(sig: *const u8, siglen: usize, msg: *const u8, msglen: usize, pk: *const u8) -> rivide_status_t;

    // SHA-3 & SHAKE
    pub fn rivide_sha3_256(out: *mut u8, in_: *const u8, inlen: usize);
    pub fn rivide_sha3_512(out: *mut u8, in_: *const u8, inlen: usize);
    pub fn rivide_shake128(out: *mut u8, outlen: usize, in_: *const u8, inlen: usize);
    pub fn rivide_shake256(out: *mut u8, outlen: usize, in_: *const u8, inlen: usize);

    // AES-GCM
    pub fn rivide_aes128_key_expand(ctx: *mut rivide_aes_key_t, key: *const u8) -> rivide_status_t;
    pub fn rivide_aes256_key_expand(ctx: *mut rivide_aes_key_t, key: *const u8) -> rivide_status_t;

    pub fn rivide_aes_gcm_encrypt(
        key: *const rivide_aes_key_t,
        iv: *const u8,
        aad: *const u8,
        aad_len: usize,
        pt: *const u8,
        pt_len: usize,
        ct: *mut u8,
        tag: *mut u8,
    ) -> rivide_status_t;

    pub fn rivide_aes_gcm_decrypt(
        key: *const rivide_aes_key_t,
        iv: *const u8,
        aad: *const u8,
        aad_len: usize,
        ct: *const u8,
        ct_len: usize,
        tag: *const u8,
        pt: *mut u8,
    ) -> rivide_status_t;
}
