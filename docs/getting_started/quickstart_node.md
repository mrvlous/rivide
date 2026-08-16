<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Quick Start: Node.js & TypeScript Integration

This guide describes how to install and use the **Rivide** native Node-API bindings in JavaScript and TypeScript environments.

## 1. Installation

Install the package using your package manager:

```bash
# npm
npm install rivide

# pnpm
pnpm add rivide

# yarn
yarn add rivide
```

## 2. TypeScript / ES Modules Usage

### ML-DSA-65 Digital Signature & Verification

Create `index.ts`:

```typescript
import { mlDsa65, utils } from 'rivide';

function main() {
    console.log(`Rivide Node.js Addon v${utils.version()}`);

    // 1. Generate ML-DSA-65 signing keypair
    const { publicKey, secretKey } = mlDsa65.keypair();
    console.log(`Public Key Length: ${publicKey.length} bytes`);
    console.log(`Secret Key Length: ${secretKey.length} bytes`);

    // 2. Sign arbitrary payload
    const document = Buffer.from('Quantum-safe digital document authorization.');
    const signature = mlDsa65.sign(document, secretKey);
    console.log(`Signature Length: ${signature.length} bytes`);

    // 3. Verify signature
    const isValid = mlDsa65.verify(signature, document, publicKey);
    console.log(`Signature Authenticity: ${isValid ? 'VALID' : 'INVALID'}`);

    // 4. Test tamper detection
    const tampered = Buffer.from('Tampered authorization payload.');
    const isTamperedValid = mlDsa65.verify(signature, tampered, publicKey);
    console.log(`Tampered Authenticity: ${isTamperedValid ? 'VALID' : 'REJECTED'}`);

    // 5. Zeroize secret key in volatile memory
    utils.cleanse(secretKey);
}

main();
```

## 3. CommonJS Usage

Create `index.js`:

```javascript
const { mlKem768, utils } = require('rivide');

// 1. Alice generates keypair
const alice = mlKem768.keypair();

// 2. Bob encapsulates shared secret under Alice's public key
const bob = mlKem768.encaps(alice.publicKey);

// 3. Alice decapsulates shared secret using her secret key
const aliceSharedSecret = mlKem768.decaps(bob.ciphertext, alice.secretKey);

// 4. Constant-time byte comparison
if (utils.ctMemcmp(aliceSharedSecret, bob.sharedSecret) === 0) {
    console.log('Quantum-safe session key exchange complete!');
}

// 5. Zeroize memory
utils.cleanse(alice.secretKey);
utils.cleanse(aliceSharedSecret);
utils.cleanse(bob.sharedSecret);
```
