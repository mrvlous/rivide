/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

'use strict';

const { mlDsa65, utils } = require('../lib/index.js');

console.log('Rivide Node.js: ML-DSA-65 Digital Signature Demonstration\n');

// 1. Generate post-quantum ML-DSA-65 signing keypair
console.log('[Signer] Generating ML-DSA-65 key pair...');
const signer = mlDsa65.keypair();
console.log(`[Signer] Public Key  : ${signer.publicKey.length} bytes`);
console.log(`[Signer] Secret Key  : ${signer.secretKey.length} bytes\n`);

// 2. Sign an authentic message payload
const message = Buffer.from('Post-quantum signed contract payload: Transfer $50,000 to Alice.');
console.log(`[Signer] Signing message: "${message.toString()}"...`);
const signature = mlDsa65.sign(message, signer.secretKey);
console.log(
    `[Signer] Generated Signature (${signature.length} bytes): ${signature.subarray(0, 32).toString('hex')}...\n`
);

// 3. [Auditor] Verify signature against message and public key
console.log('[Auditor] Verifying digital signature...');
const isValid = mlDsa65.verify(signature, message, signer.publicKey);
if (isValid) {
    console.log('[SUCCESS] Signature is VALID and AUTHENTIC!\n');
} else {
    console.error('[ERROR] Signature verification failed!');
    process.exit(1);
}

// 4. Test tamper resistance
const tamperedMessage = Buffer.from(
    'Post-quantum signed contract payload: Transfer $500,000 to Alice.'
);
console.log(`[Auditor] Testing tampered message: "${tamperedMessage.toString()}"...`);
const isTamperedValid = mlDsa65.verify(signature, tamperedMessage, signer.publicKey);
if (!isTamperedValid) {
    console.log('[SUCCESS] Tampered message correctly REJECTED!');
} else {
    console.error('[ERROR] Tampered message falsely accepted!');
    process.exit(1);
}

// 5. Cleanse sensitive private key
utils.cleanse(signer.secretKey);
