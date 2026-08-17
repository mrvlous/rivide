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
const { sha3, aesGcm, utils, constants } = require('../lib/index.js');

test('SHA-3: SHA3-256 and SHA3-512 Known Vectors', () => {
    // SHA3-256 of empty string: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    const emptyDigest = sha3.sha3_256(Buffer.alloc(0));
    assert.strictEqual(emptyDigest.length, 32);
    assert.strictEqual(
        emptyDigest.toString('hex'),
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    );

    // SHA3-512 of empty string: a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
    const empty512 = sha3.sha3_512(Buffer.alloc(0));
    assert.strictEqual(empty512.length, 64);
    assert.strictEqual(
        empty512.toString('hex'),
        'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    );
});

test('SHAKE: SHAKE-128 and SHAKE-256 XOF', () => {
    const out128 = sha3.shake128(Buffer.from('Hello PQC'), 48);
    assert.strictEqual(out128.length, 48);

    const out256 = sha3.shake256(Buffer.from('Hello PQC'), 64);
    assert.strictEqual(out256.length, 64);
});

test('AES-GCM: AES-128 and AES-256 AEAD Roundtrip', () => {
    const key128 = utils.randombytes(16);
    const key256 = utils.randombytes(32);
    const iv = utils.randombytes(12);
    const plaintext = Buffer.from('Quantum-safe encrypted symmetric payload message!');
    const aad = Buffer.from('Protocol-Header-v1.0');

    // AES-128-GCM
    const enc128 = aesGcm.encrypt128(key128, iv, plaintext, aad);
    assert.strictEqual(enc128.ciphertext.length, plaintext.length);
    assert.strictEqual(enc128.tag.length, 16);
    const dec128 = aesGcm.decrypt128(key128, iv, enc128.ciphertext, enc128.tag, aad);
    assert.deepStrictEqual(dec128, plaintext);

    // AES-256-GCM
    const enc256 = aesGcm.encrypt256(key256, iv, plaintext, aad);
    assert.strictEqual(enc256.ciphertext.length, plaintext.length);
    assert.strictEqual(enc256.tag.length, 16);
    const dec256 = aesGcm.decrypt256(key256, iv, enc256.ciphertext, enc256.tag, aad);
    assert.deepStrictEqual(dec256, plaintext);

    // Tampered tag rejection
    const badTag = Buffer.from(enc256.tag);
    badTag[0] ^= 0xff;
    assert.throws(() => {
        aesGcm.decrypt256(key256, iv, enc256.ciphertext, badTag, aad);
    }, /authentication verification failed/);
});

test('Utils: Randomness, Cleanse, CT Memcmp, and SIMD Capabilities', () => {
    const rand = utils.randombytes(32);
    assert.strictEqual(rand.length, 32);

    const secret = Buffer.from('super-sensitive-master-private-key-material');
    utils.cleanse(secret);
    assert.strictEqual(
        secret.every((b) => b === 0),
        true
    );

    const a = Buffer.from([1, 2, 3, 4]);
    const b = Buffer.from([1, 2, 3, 4]);
    const c = Buffer.from([1, 2, 3, 5]);
    assert.strictEqual(utils.ctMemcmp(a, b), 0);
    assert.notStrictEqual(utils.ctMemcmp(a, c), 0);

    const caps = utils.getSimdCaps();
    assert.strictEqual(typeof caps.hasAesni, 'boolean');
    assert.strictEqual(typeof caps.hasAvx2, 'boolean');
    assert.strictEqual(typeof caps.bitmask, 'number');

    assert.strictEqual(utils.version(), '1.1.3');
});
