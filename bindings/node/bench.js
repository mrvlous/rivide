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

const { mlKem768, mlKem1024, mlDsa65, mlDsa87, sha3, aesGcm, utils } = require('./lib/index.js');

function benchmark(name, fn, iterations = 1000) {
    // Warm up
    for (let i = 0; i < 50; i++) fn();

    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) {
        fn();
    }
    const end = process.hrtime.bigint();

    const durationSec = Number(end - start) / 1e9;
    const opsPerSec = iterations / durationSec;
    const usPerOp = (durationSec / iterations) * 1e6;

    console.log(
        `  ${name.padEnd(28)} : ${opsPerSec.toFixed(2).padStart(9)} ops/sec (${usPerOp.toFixed(2).padStart(7)} us/op)`
    );
}

console.log(`Rivide Node.js (Node-API) Post-Quantum Cryptography Benchmark Suite v${utils.version()}\n`);
console.log(`Node.js Runtime : ${process.version} (${process.arch}-${process.platform})`);
const caps = utils.getSimdCaps();
console.log(`Hardware SIMD   : AVX2: ${caps.hasAvx2 ? 'YES' : 'NO'}, AES-NI: ${caps.hasAesni ? 'YES' : 'NO'}, NEON: ${caps.hasNeon ? 'YES' : 'NO'}\n`);

const iters = 1000;

console.log('NIST FIPS 203 ML-KEM Benchmarks:');
let kem768Kp = mlKem768.keypair();
let kem768Enc = mlKem768.encaps(kem768Kp.publicKey);
benchmark('ML-KEM-768 KeyGen', () => mlKem768.keypair(), iters);
benchmark('ML-KEM-768 Encaps', () => mlKem768.encaps(kem768Kp.publicKey), iters);
benchmark('ML-KEM-768 Decaps', () => mlKem768.decaps(kem768Enc.ciphertext, kem768Kp.secretKey), iters);

console.log('');
let kem1024Kp = mlKem1024.keypair();
let kem1024Enc = mlKem1024.encaps(kem1024Kp.publicKey);
benchmark('ML-KEM-1024 KeyGen', () => mlKem1024.keypair(), iters);
benchmark('ML-KEM-1024 Encaps', () => mlKem1024.encaps(kem1024Kp.publicKey), iters);
benchmark('ML-KEM-1024 Decaps', () => mlKem1024.decaps(kem1024Enc.ciphertext, kem1024Kp.secretKey), iters);

console.log('\nNIST FIPS 204 ML-DSA Benchmarks:');
let dsa65Kp = mlDsa65.keypair();
const sampleMsg = Buffer.from('Quantum-safe payload for digital signature benchmarking.');
let dsa65Sig = mlDsa65.sign(sampleMsg, dsa65Kp.secretKey);
benchmark('ML-DSA-65 KeyGen', () => mlDsa65.keypair(), iters);
benchmark('ML-DSA-65 Sign', () => mlDsa65.sign(sampleMsg, dsa65Kp.secretKey), iters);
benchmark('ML-DSA-65 Verify', () => mlDsa65.verify(dsa65Sig, sampleMsg, dsa65Kp.publicKey), iters);

console.log('');
let dsa87Kp = mlDsa87.keypair();
let dsa87Sig = mlDsa87.sign(sampleMsg, dsa87Kp.secretKey);
benchmark('ML-DSA-87 KeyGen', () => mlDsa87.keypair(), iters);
benchmark('ML-DSA-87 Sign', () => mlDsa87.sign(sampleMsg, dsa87Kp.secretKey), iters);
benchmark('ML-DSA-87 Verify', () => mlDsa87.verify(dsa87Sig, sampleMsg, dsa87Kp.publicKey), iters);

console.log('\nSymmetric Primitives Benchmarks:');
const payload4KB = Buffer.alloc(4096, 0x42);
const key32 = Buffer.alloc(32, 0x01);
const iv12 = Buffer.alloc(12, 0x02);
let encRes = aesGcm.encrypt256(key32, iv12, payload4KB);
benchmark('SHA3-256 (4 KB)', () => sha3.sha3_256(payload4KB), iters);
benchmark('SHAKE-256 (4 KB -> 32B)', () => sha3.shake256(payload4KB, 32), iters);
benchmark('AES-256-GCM Encrypt (4 KB)', () => aesGcm.encrypt256(key32, iv12, payload4KB), iters);
benchmark('AES-256-GCM Decrypt (4 KB)', () => aesGcm.decrypt256(key32, iv12, encRes.ciphertext, encRes.tag), iters);

console.log('\n[SUCCESS] Node.js Benchmark Suite Execution Complete.');
