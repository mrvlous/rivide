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

//! Strongly typed error definitions for the Rivide Rust crate.

use std::fmt;

/// The primary error type for all Rivide cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RivideError {
    /// Invalid parameter supplied to a cryptographic routine (e.g. null buffer or invalid length).
    InvalidParameter,
    /// Digital signature or AEAD authentication tag verification failed.
    VerificationFailed,
    /// Operating system CSPRNG failed to supply requested entropy bytes.
    EntropyFailure,
    /// Internal cryptographic or hardware state fault.
    InternalError,
}

impl fmt::Display for RivideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RivideError::InvalidParameter => write!(f, "Invalid parameter or buffer size"),
            RivideError::VerificationFailed => write!(f, "Cryptographic verification failed"),
            RivideError::EntropyFailure => write!(f, "Failed to retrieve OS entropy bytes"),
            RivideError::InternalError => write!(f, "Internal cryptographic error"),
        }
    }
}

impl std::error::Error for RivideError {}

impl RivideError {
    /// Converts a raw C status code into a Rust Result.
    pub(crate) fn from_status(status: crate::sys::rivide_status_t) -> Result<(), Self> {
        match status {
            crate::sys::RIVIDE_SUCCESS => Ok(()),
            crate::sys::RIVIDE_ERR_INVALID_PARAM => Err(RivideError::InvalidParameter),
            crate::sys::RIVIDE_ERR_VERIFICATION_FAILED => Err(RivideError::VerificationFailed),
            crate::sys::RIVIDE_ERR_ENTROPY_FAILURE => Err(RivideError::EntropyFailure),
            _ => Err(RivideError::InternalError),
        }
    }
}
