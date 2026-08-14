/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { mlDsa65, mlDsa87, constants } = require('../lib/index.js');

test('ML-DSA-65: KeyGen, Sign, and Verify Roundtrip', () => {
    const signer = mlDsa65.keypair();
    assert.strictEqual(signer.publicKey.length, constants.ML_DSA_65_PK_BYTES);
    assert.strictEqual(signer.secretKey.length, constants.ML_DSA_65_SK_BYTES);

    const message = Buffer.from('Post-quantum signed message payload using Rivide Node.js bindings.');
    const signature = mlDsa65.sign(message, signer.secretKey);
    assert.strictEqual(signature.length, constants.ML_DSA_65_SIG_BYTES);

    const isValid = mlDsa65.verify(signature, message, signer.publicKey);
    assert.strictEqual(isValid, true);
});

test('ML-DSA-65: Tamper Rejection on Message and Signature', () => {
    const signer = mlDsa65.keypair();
    const message = Buffer.from('Important financial transfer contract.');
    const signature = mlDsa65.sign(message, signer.secretKey);

    // Tampered message
    const tamperedMessage = Buffer.from('Important financial transfer contract!');
    assert.strictEqual(mlDsa65.verify(signature, tamperedMessage, signer.publicKey), false);

    // Tampered signature
    const tamperedSig = Buffer.from(signature);
    tamperedSig[20] ^= 0x01;
    assert.strictEqual(mlDsa65.verify(tamperedSig, message, signer.publicKey), false);
});

test('ML-DSA-87: KeyGen, Sign, and Verify Roundtrip', () => {
    const signer = mlDsa87.keypair();
    assert.strictEqual(signer.publicKey.length, constants.ML_DSA_87_PK_BYTES);
    assert.strictEqual(signer.secretKey.length, constants.ML_DSA_87_SK_BYTES);

    const message = Buffer.from('Security Category 5 sovereign certificate payload.');
    const signature = mlDsa87.sign(message, signer.secretKey);
    assert.strictEqual(signature.length, constants.ML_DSA_87_SIG_BYTES);

    const isValid = mlDsa87.verify(signature, message, signer.publicKey);
    assert.strictEqual(isValid, true);
});

test('ML-DSA: Strict siglen and Buffer Validation', () => {
    const signer = mlDsa65.keypair();
    const message = Buffer.from('Test message');

    // Invalid truncated signature length
    const invalidSig = Buffer.alloc(100);
    assert.strictEqual(mlDsa65.verify(invalidSig, message, signer.publicKey), false);
});
