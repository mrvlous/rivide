<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Integration Guide: Post-Quantum TLS 1.3 Handshake

This integration guide demonstrates how to combine **ML-KEM-768** key encapsulation and **ML-DSA-65** digital signatures to build a simulated Post-Quantum TLS 1.3 handshake protocol.

## Protocol Handshake Overview

```
    Client                                           Server
      |                                                |
      | ------------- Client Hello ------------------> |
      |               (Supported Groups: ML-KEM-768)   |
      |                                                |
      | <------------ Server Hello ------------------- |
      |               - Server ML-KEM-768 Ephemeral PK |
      |               - ML-DSA-65 Certificate & Sig    |
      |                                                |
      | [Verify Server Sig & Encapsulate Key]          |
      |                                                |
      | ------------- Finished (ML-KEM CT) ---------> |
      |                                                |
      | [Decapsulate Key & Establish Tunnel]           |
      v                                                v
```

## Sample Code Reference

See [`examples/protocol/tls_handshake_pqc.c`](../../examples/protocol/tls_handshake_pqc.c) for full executable code.

```c
#include "rivide/pqc/ml_dsa.h"
#include "rivide/pqc/ml_kem.h"

void tls13_pqc_handshake_demo(void) {
    uint8_t dsa_pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t dsa_sk[RIVIDE_ML_DSA_65_SK_BYTES];
    uint8_t kem_pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t kem_sk[RIVIDE_ML_KEM_768_SK_BYTES];
    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss_client[RIVIDE_ML_KEM_768_SS_BYTES];
    uint8_t ss_server[RIVIDE_ML_KEM_768_SS_BYTES];
    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen;

    /* 1. Server provisions ML-DSA-65 identity keypair */
    rivide_ml_dsa_65_keygen(dsa_pk, dsa_sk);

    /* 2. Server generates ephemeral ML-KEM-768 key exchange keypair */
    rivide_ml_kem_768_keygen(kem_pk, kem_sk);

    /* 3. Server signs ephemeral public key with ML-DSA-65 key */
    rivide_ml_dsa_65_sign(sig, &siglen, kem_pk, sizeof(kem_pk), dsa_sk);

    /* 4. Client verifies server handshake signature */
    if (rivide_ml_dsa_65_verify(sig, siglen, kem_pk, sizeof(kem_pk), dsa_pk) == RIVIDE_SUCCESS) {
        /* 5. Client encapsulates master secret */
        rivide_ml_kem_768_encaps(ct, ss_client, kem_pk);

        /* 6. Server decapsulates master secret */
        rivide_ml_kem_768_decaps(ss_server, ct, kem_sk);
    }
}
```
