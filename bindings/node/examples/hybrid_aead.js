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

const { mlKem768, aesGcm, utils } = require('../lib/index.js');

console.log('Rivide Node.js: Hybrid PQC + AES-256-GCM Secure Channel\n');

// 1. [Server] Generate ephemeral ML-KEM-768 keypair
console.log('[Server] Generating ephemeral ML-KEM-768 keypair...');
const server = mlKem768.keypair();

// 2. [Client] Encapsulate 256-bit symmetric session key
console.log('[Client] Encapsulating shared symmetric key under server public key...');
const kemResult = mlKem768.encaps(server.publicKey);
const sessionKey = kemResult.sharedSecret; // 32-byte quantum-safe symmetric key

// 3. [Client] Encrypt message payload using AES-256-GCM AEAD
const payload = Buffer.from('TOP SECRET: Quantum-safe encrypted banking wire instructions.');
const iv = utils.randombytes(12);
const aad = Buffer.from('Protocol:TLS1.3-PQC-Hybrid');

console.log(`[Client] Encrypting payload (${payload.length} bytes) using AES-256-GCM...`);
const encrypted = aesGcm.encrypt256(sessionKey, iv, payload, aad);
console.log(`[Client] Ciphertext: ${encrypted.ciphertext.toString('hex')}`);
console.log(`[Client] Auth Tag  : ${encrypted.tag.toString('hex')}\n`);

// 4. [Network] Transmit (kemResult.ciphertext, iv, encrypted.ciphertext, encrypted.tag, aad)
console.log('[Network] Transmitting quantum-safe encapsulated packet to Server...\n');

// 5. [Server] Decapsulate symmetric session key
console.log('[Server] Decapsulating session key from KEM ciphertext...');
const serverSessionKey = mlKem768.decaps(kemResult.ciphertext, server.secretKey);

// 6. [Server] Authenticate and decrypt AES-256-GCM payload
console.log('[Server] Authenticating and decrypting payload...');
const decrypted = aesGcm.decrypt256(serverSessionKey, iv, encrypted.ciphertext, encrypted.tag, aad);
console.log(`[Server] Decrypted Plaintext: "${decrypted.toString('utf8')}"\n`);

if (decrypted.equals(payload)) {
    console.log('[SUCCESS] Hybrid PQC + AES-256-GCM Secure Tunnel Verified!');
} else {
    console.error('[ERROR] Decryption mismatch!');
    process.exit(1);
}

// 7. Cleanse memory
utils.cleanse(server.secretKey);
utils.cleanse(sessionKey);
utils.cleanse(serverSessionKey);
