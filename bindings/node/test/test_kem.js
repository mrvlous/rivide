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

const test = require('node:test');
const assert = require('node:assert');
const { mlKem768, mlKem1024, constants, ctMemcmp } = require('../lib/index.js');

test('ML-KEM-768: KeyGen, Encaps, and Decaps Roundtrip', () => {
    const alice = mlKem768.keypair();
    assert.strictEqual(alice.publicKey.length, constants.ML_KEM_768_PK_BYTES);
    assert.strictEqual(alice.secretKey.length, constants.ML_KEM_768_SK_BYTES);

    const bob = mlKem768.encaps(alice.publicKey);
    assert.strictEqual(bob.ciphertext.length, constants.ML_KEM_768_CT_BYTES);
    assert.strictEqual(bob.sharedSecret.length, constants.ML_KEM_768_SS_BYTES);

    const aliceSharedSecret = mlKem768.decaps(bob.ciphertext, alice.secretKey);
    assert.strictEqual(aliceSharedSecret.length, constants.ML_KEM_768_SS_BYTES);

    assert.strictEqual(ctMemcmp(aliceSharedSecret, bob.sharedSecret), 0);
    assert.deepStrictEqual(aliceSharedSecret, bob.sharedSecret);
});

test('ML-KEM-768: Implicit Rejection on Tampered Ciphertext', () => {
    const alice = mlKem768.keypair();
    const bob = mlKem768.encaps(alice.publicKey);

    // Corrupt one byte of ciphertext
    const tamperedCt = Buffer.from(bob.ciphertext);
    tamperedCt[10] ^= 0xff;

    const aliceDecaps = mlKem768.decaps(tamperedCt, alice.secretKey);
    assert.notStrictEqual(ctMemcmp(aliceDecaps, bob.sharedSecret), 0);
});

test('ML-KEM-1024: KeyGen, Encaps, and Decaps Roundtrip', () => {
    const alice = mlKem1024.keypair();
    assert.strictEqual(alice.publicKey.length, constants.ML_KEM_1024_PK_BYTES);
    assert.strictEqual(alice.secretKey.length, constants.ML_KEM_1024_SK_BYTES);

    const bob = mlKem1024.encaps(alice.publicKey);
    assert.strictEqual(bob.ciphertext.length, constants.ML_KEM_1024_CT_BYTES);
    assert.strictEqual(bob.sharedSecret.length, constants.ML_KEM_1024_SS_BYTES);

    const aliceSharedSecret = mlKem1024.decaps(bob.ciphertext, alice.secretKey);
    assert.strictEqual(aliceSharedSecret.length, constants.ML_KEM_1024_SS_BYTES);

    assert.strictEqual(ctMemcmp(aliceSharedSecret, bob.sharedSecret), 0);
});

test('ML-KEM: Buffer Validation and Error Handling', () => {
    assert.throws(() => {
        mlKem768.encaps(Buffer.alloc(100)); // Invalid PK length
    }, /publicKey must be a Buffer of exactly 1184 bytes/);

    assert.throws(() => {
        mlKem1024.encaps(Buffer.alloc(100)); // Invalid PK length
    }, /publicKey must be a Buffer of exactly 1568 bytes/);
});
