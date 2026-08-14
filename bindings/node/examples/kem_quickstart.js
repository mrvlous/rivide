/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 */

'use strict';

const { mlKem768, ctMemcmp, utils } = require('../lib/index.js');

console.log('=== Rivide Node.js: ML-KEM-768 Key Exchange Demonstration ===\n');

// 1. [Alice] Generate post-quantum ML-KEM-768 keypair
console.log('[Alice] Generating ML-KEM-768 key pair...');
const alice = mlKem768.keypair();
console.log(`[Alice] Public Key  : ${alice.publicKey.length} bytes`);
console.log(`[Alice] Secret Key  : ${alice.secretKey.length} bytes\n`);

// 2. [Bob] Encapsulate a shared secret using Alice's public key
console.log('[Bob] Encapsulating shared secret using Alice\'s public key...');
const bob = mlKem768.encaps(alice.publicKey);
console.log(`[Bob] Ciphertext    : ${bob.ciphertext.length} bytes`);
console.log(`[Bob] Shared Secret : ${bob.sharedSecret.toString('hex')}\n`);

// 3. [Alice] Decapsulate the ciphertext using her secret key
console.log('[Alice] Decapsulating shared secret from ciphertext...');
const aliceSharedSecret = mlKem768.decaps(bob.ciphertext, alice.secretKey);
console.log(`[Alice] Shared Secret: ${aliceSharedSecret.toString('hex')}\n`);

// 4. Verify shared secret match in constant-time
if (ctMemcmp(aliceSharedSecret, bob.sharedSecret) === 0) {
    console.log('[SUCCESS] Quantum-safe shared secrets match perfectly!');
} else {
    console.error('[ERROR] Shared secret mismatch!');
    process.exit(1);
}

// 5. Securely wipe secret key material from memory
utils.cleanse(alice.secretKey);
utils.cleanse(aliceSharedSecret);
utils.cleanse(bob.sharedSecret);
console.log('[Memory] Sensitive private key material cleansed from RAM.');
