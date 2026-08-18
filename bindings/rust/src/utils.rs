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

//! Cryptographic utilities, secure memory zeroization, and CPU feature detection.

use crate::error::RivideError;
use crate::sys::*;
use std::ffi::CStr;

/// Hardware acceleration features detected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuFeatures {
    pub has_aesni: bool,
    pub has_arm_ce: bool,
    pub has_avx2: bool,
    pub has_neon: bool,
    pub bitmask: u32,
}

/// Securely zeroizes memory to prevent compiler dead-store elimination.
pub fn cleanse(buffer: &mut [u8]) {
    unsafe {
        rivide_cleanse(
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len(),
        );
    }
}

/// Fills the destination buffer with cryptographically secure random bytes from OS CSPRNG.
pub fn randombytes_into(buffer: &mut [u8]) -> Result<(), RivideError> {
    let status = unsafe { rivide_randombytes(buffer.as_mut_ptr(), buffer.len()) };
    RivideError::from_status(status)
}

/// Generates a vector of `len` cryptographically secure random bytes from OS CSPRNG.
pub fn randombytes(len: usize) -> Result<Vec<u8>, RivideError> {
    let mut buf = vec![0u8; len];
    randombytes_into(&mut buf)?;
    Ok(buf)
}

/// Compares two byte slices in constant time.
///
/// Returns `0` if both slices are identical, or non-zero otherwise.
pub fn ct_memcmp(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return -1;
    }
    unsafe {
        rivide_ct_memcmp(
            a.as_ptr() as *const std::os::raw::c_void,
            b.as_ptr() as *const std::os::raw::c_void,
            a.len(),
        )
    }
}

/// Returns the detected hardware acceleration CPU feature flags.
pub fn get_cpu_features() -> CpuFeatures {
    let mask = unsafe { rivide_get_cpu_features() };
    CpuFeatures {
        has_aesni: (mask & RIVIDE_CPU_AESNI) != 0,
        has_arm_ce: (mask & RIVIDE_CPU_ARM_CE) != 0,
        has_avx2: (mask & RIVIDE_CPU_AVX2) != 0,
        has_neon: (mask & RIVIDE_CPU_ARM_NEON) != 0,
        bitmask: mask,
    }
}

/// Returns the Rivide library version string (e.g. `"1.1.5"`).
pub fn version() -> &'static str {
    let ptr = unsafe { rivide_version_string() };
    if ptr.is_null() {
        "1.1.5"
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().unwrap_or("1.1.5") }
    }
}
