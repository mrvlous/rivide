# Symmetric Cryptographic Primitives

This document describes the design and implementation of Rivide's symmetric cryptographic primitives: the **Keccak-f[1600]** sponge engine (SHA-3 & SHAKE) and the **AES-128/256-GCM** AEAD cipher.

---

## 1. Keccak Sponge Engine & SHA-3 / SHAKE (NIST FIPS 202)

Implemented in [`src/crypto/sha3.c`](../../src/crypto/sha3.c), the Keccak engine forms the foundational hash function for all post-quantum algorithms in Rivide.

### Keccak-f[1600] Permutation
*   **State Matrix**: Operates on a $5 \times 5$ grid of 64-bit lanes ($1600$ bits total).
*   **Round Structure**: Executes $24$ rounds consisting of five continuous step mappings:
    1.  $\theta$ (Theta): Parity mixing across 5-lane columns.
    2.  $\rho$ (Rho): Bitwise left rotations with precomputed offsets.
    3.  $\pi$ (Pi): Fixed transposition of lane coordinates.
    4.  $\chi$ (Chi): Non-linear row-wise bitwise logic ($x \oplus (\sim y \land z)$).
    5.  $\iota$ (Iota): Asymmetry breaking via round constants (`keccak_rc`).

### Supported Algorithms & Rates

| Algorithm | Type | Output Size | Sponge Rate ($r$) | Domain Sep |
| :--- | :--- | :--- | :--- | :--- |
| **SHA3-256** | Hash | 32 bytes | 136 bytes ($1088$ bits) | `0x06` |
| **SHA3-512** | Hash | 64 bytes | 72 bytes ($576$ bits) | `0x06` |
| **SHAKE-128** | XOF | Variable | 168 bytes ($1344$ bits) | `0x1F` |
| **SHAKE-256** | XOF | Variable | 136 bytes ($1088$ bits) | `0x1F` |

---

## 2. AES-128 / AES-256-GCM AEAD (NIST SP 800-38D)

Implemented in [`src/crypto/aes_gcm.c`](../../src/crypto/aes_gcm.c), AES-GCM provides Authenticated Encryption with Associated Data (AEAD).

### Constant-Time Software AES Core
*   **Bitwise Operation**: Avoids traditional lookup T-tables to eliminate microarchitectural cache-timing vulnerabilities on target hardware lacking AES-NI or ARM CE instructions.
*   **Key Schedule**: Expands 128-bit keys into 10 round keys (44 words) and 256-bit keys into 14 round keys (60 words).
*   **Rijndael Rounds**: Performs `SubBytes` (S-Box), `ShiftRows`, `MixColumns` (GF($2^8$) Galois Field doubling via `xtime`), and `AddRoundKey`.

### Galois/Counter Mode (GCM)
*   **CTR Encryption**: Encrypts plaintext using incremental counter blocks starting from $J_0 + 1$.
*   **GHASH Authentication**: Computes a 128-bit MAC over associated data (AAD) and ciphertext using field multiplication in Galois Field $\mathrm{GF}(2^{128})$ modulo $x^{128} + x^7 + x^2 + x + 1$.
