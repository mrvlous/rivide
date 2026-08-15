<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# NIST FIPS 203: ML-KEM Algorithm Specification

This document provides the mathematical foundation, parameter definitions, and algorithmic workflows for the **Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)** standard implemented in **Rivide**.

---

## 1. Mathematical Framework

ML-KEM operates over the cyclotomic polynomial quotient ring:

$$\mathcal{R}_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$

where the prime modulus is:

$$q = 3329$$

The ring degree is $n = 256$. Elements in $\mathcal{R}_q$ are represented by vectors of polynomials of dimension $k \in \{3, 4\}$ depending on the targeted NIST security level.

---

## 2. Parameter Sets

| Parameter | ML-KEM-768 | ML-KEM-1024 | Description |
| :--- | :--- | :--- | :--- |
| **NIST Security Level** | Category 3 (AES-192) | Category 5 (AES-256) | Quantum security classification |
| **Matrix Dimension ($k$)** | `3` | `4` | Rank of polynomial matrix $\mathbf{A} \in \mathcal{R}_q^{k \times k}$ |
| **Noise Parameter ($\eta_1$)** | `2` | `2` | Centered Binomial Distribution width for secrets |
| **Noise Parameter ($\eta_2$)** | `2` | `2` | Centered Binomial Distribution width for errors |
| **Compression Factor ($d_u$)** | `10` | `11` | Bit-depth of compressed vector $\mathbf{u}$ |
| **Compression Factor ($d_v$)** | `4` | `5` | Bit-depth of compressed polynomial $v$ |
| **Public Key Length** | `1184` bytes | `1568` bytes | Encoded $(\mathbf{t}, \rho)$ |
| **Secret Key Length** | `2400` bytes | `3168` bytes | Encoded $(\mathbf{s}, \text{pk}, H(\text{pk}), z)$ |
| **Ciphertext Length** | `1088` bytes | `1568` bytes | Encoded $(\mathbf{u}, v)$ |
| **Shared Secret Length** | `32` bytes | `32` bytes | Derived symmetric session key $K$ |

---

## 3. Centered Binomial Distribution ($\text{CBD}_\eta$)

Small error vectors $\mathbf{s}, \mathbf{e}$ are sampled from the Centered Binomial Distribution $\text{CBD}_\eta$:

$$(a_1, \dots, a_\eta), (b_1, \dots, b_\eta) \xleftarrow{\$} \{0, 1\}^\eta, \quad x = \sum_{i=1}^\eta (a_i - b_i) \in [-\eta, \eta]$$

For $\eta = 2$, each sample $x \in \{-2, -1, 0, 1, 2\}$ is generated from 4 pseudorandom bits derived via SHAKE-256 expansion.

---

## 4. Key Encapsulation Workflow

```
       Alice (Recipient)                          Bob (Sender)
       -----------------                          ------------
   1. (pk, sk) = KeyGen()
             |
             |-------- Public Key (pk) --------->
             |                                    2. (ct, ss) = Encaps(pk)
             |                                          |
             |<------- Ciphertext (ct) ----------+------+
             |
   3. ss' = Decaps(ct, sk)
             |
   4. Assert ss' == ss
```

### IND-CCA2 Fujisaki-Okamoto Transform

To achieve Indistinguishability under Chosen-Ciphertext Attacks (**IND-CCA2**), ML-KEM wraps an underlying CPA-secure Public Key Encryption (PKE) scheme using the Fujisaki-Okamoto (FO) transform:

1. **Decryption**: $\mathbf{m}' = \text{PKE.Decrypt}(\text{sk}_{pke}, \text{ct})$.
2. **Re-encryption**: $(\mathbf{u}', v') = \text{PKE.Encrypt}(\text{pk}, \mathbf{m}', \text{coins}' = G(\mathbf{m}' \parallel H(\text{pk})))$.
3. **Implicit Rejection**:
   $$\text{ct} \stackrel{?}{=} (\mathbf{u}', v')$$
   If matched: $K = J(K_{true} \parallel H(\text{ct}))$.  
   If mismatched: $K = J(z \parallel H(\text{ct}))$ using pseudorandom reject value $z$ to prevent chosen-ciphertext oracle leakage.
