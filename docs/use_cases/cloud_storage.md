# Integration Guide: Post-Quantum Secure Vault Storage

This integration guide demonstrates how to construct a quantum-safe encrypted storage vault using **ML-KEM-1024**, **SHA3-512**, and **AES-256-GCM**.

## Vault Architecture

```
+------------------------------------------------------------------------+
|                          Encrypted Vault Header                        |
|  +--------------------------------+---------------------------------+  |
|  | ML-KEM-1024 Ciphertext         | AES-256-GCM Auth Tag            |  |
|  | (1568 bytes)                   | (16 bytes)                      |  |
|  +--------------------------------+---------------------------------+  |
|                                                                        |
|                          Encrypted Payload Body                        |
|  +------------------------------------------------------------------+  |
|  | AES-256-GCM Encrypted File Contents                            |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
```

## Key Derivation Pipeline

1. **ML-KEM-1024 Encapsulation**: Produces a 32-byte PQC shared secret key $K_{\text{pqc}}$ and 1568-byte ciphertext $C_{\text{kem}}$.
2. **SHA3-512 KDF**: Expands $K_{\text{pqc}}$ into a 256-bit AES encryption key $K_{\text{aes}}$ and a 96-bit IV:
   $$\text{KDF}(K_{\text{pqc}}) = \text{SHA3-512}(K_{\text{pqc}} \parallel \text{"VaultKDF"}) = K_{\text{aes}} \parallel \text{IV}$$
3. **AES-256-GCM AEAD Encryption**: Encrypts and authenticates file payload using $K_{\text{aes}}$ and IV.

## Sample Code Reference

See [`examples/storage/secure_vault_storage.c`](file:///home/v1lnv/Documents/Projects/rivide/examples/storage/secure_vault_storage.c) for full executable code.
