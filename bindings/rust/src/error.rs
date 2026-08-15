// SPDX-License-Identifier: MIT
//
// Rivide Post-Quantum Cryptography Library
// Copyright (C) 2026 Moh. Ananda Firmansyah Putra

//! Error types for the Rivide cryptographic library.

use std::fmt;

/// The error type for Rivide operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RivideError {
    /// Invalid parameter supplied to a cryptographic routine.
    InvalidParameter,
    /// Digital signature or authentication tag verification failed.
    VerificationFailed,
    /// Operating system CSPRNG failed to supply requested entropy bytes.
    EntropyFailure,
    /// Internal cryptographic or system failure.
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
