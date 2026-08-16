<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Use Case: Detached Document Signing & PDF Verification

This architectural blueprint demonstrates how to generate and verify post-quantum detached digital signatures for legally binding contracts, firmware binaries, and financial transactions using NIST FIPS 204 ML-DSA.

## 1. Architecture Overview

In a detached signature workflow:
1. The signer computes the cryptographic hash of the document or binary file.
2. The signer generates an ML-DSA-65 signature over the document hash.
3. The signature file (`document.pdf.pqc.sig`) is stored or transmitted alongside the original document.
4. Any third party with the signer's public key can verify the integrity and non-repudiation of the document without altering the original file.

## 2. C99 Implementation Pattern

```c
#include <stdio.h>
#include <string.h>
#include <rivide/rivide.h>

int sign_document(const uint8_t *doc, size_t doclen, const uint8_t *sk, uint8_t *sig_out) {
    size_t siglen = RIVIDE_ML_DSA_65_BYTES;
    return rivide_ml_dsa_65_sign(sig_out, &siglen, doc, doclen, sk);
}

int verify_document(const uint8_t *doc, size_t doclen, const uint8_t *pk, const uint8_t *sig) {
    return rivide_ml_dsa_65_verify(sig, RIVIDE_ML_DSA_65_BYTES, doc, doclen, pk);
}
```
