# Integration Guide: Post-Quantum Signed Tokens & Detached Documents

This integration guide describes how to issue and verify quantum-resistant API authentication tokens and detached digital documents using **ML-DSA-87** (NIST Security Category 5).

## Detached Signature Workflow

```
 +------------------------+                      +------------------------+
 |    Document / Payload  |                      |  Detached Signature    |
 |  (e.g., PDF / JWT B64) |                      |  (4627 bytes ML-DSA)   |
 +-----------+------------+                      +-----------+------------+
             |                                               |
             +-----------------------+-----------------------+
                                     |
                           +---------v---------+
                           |  ML-DSA-87 Verify |
                           |  against Public K |
                           +---------+---------+
                                     |
                           +---------v---------+
                           |  Authentic / Fail |
                           +-------------------+
```

## Sample Code Reference

See [`examples/document/detached_pdf_signer.c`](file:///home/v1lnv/Documents/Projects/rivide/examples/document/detached_pdf_signer.c) for full executable code.
