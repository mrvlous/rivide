/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 */

'use strict';

const path = require('path');

let native;
try {
    native = require(path.join(__dirname, '..', 'build', 'Release', 'rivide_native.node'));
} catch (e1) {
    try {
        native = require(path.join(__dirname, '..', 'build', 'Debug', 'rivide_native.node'));
    } catch (e2) {
        throw new Error(
            'Failed to load Rivide native binary. Please run "npm run build" or "node-gyp rebuild" in bindings/node.\n' +
            e1.message
        );
    }
}

/**
 * Normalizes an input to a standard Buffer.
 * @param {Buffer | Uint8Array | string} input
 * @returns {Buffer}
 */
function toBuffer(input) {
    if (Buffer.isBuffer(input)) {
        return input;
    }
    if (input instanceof Uint8Array) {
        return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    }
    if (typeof input === 'string') {
        return Buffer.from(input, 'utf8');
    }
    throw new TypeError('Input must be a Buffer, Uint8Array, or string');
}

/**
 * Cryptographic constants & buffer sizes
 */
const constants = Object.freeze({
    ML_KEM_768_PK_BYTES: 1184,
    ML_KEM_768_SK_BYTES: 2400,
    ML_KEM_768_CT_BYTES: 1088,
    ML_KEM_768_SS_BYTES: 32,

    ML_KEM_1024_PK_BYTES: 1568,
    ML_KEM_1024_SK_BYTES: 3168,
    ML_KEM_1024_CT_BYTES: 1568,
    ML_KEM_1024_SS_BYTES: 32,

    ML_DSA_65_PK_BYTES: 1952,
    ML_DSA_65_SK_BYTES: 4032,
    ML_DSA_65_SIG_BYTES: 3309,

    ML_DSA_87_PK_BYTES: 2592,
    ML_DSA_87_SK_BYTES: 4896,
    ML_DSA_87_SIG_BYTES: 4627,

    SHA3_256_BYTES: 32,
    SHA3_512_BYTES: 64,
    AES_GCM_IV_BYTES: 12,
    AES_GCM_TAG_BYTES: 16
});

/**
 * NIST FIPS 203 ML-KEM-768
 */
const mlKem768 = Object.freeze({
    keypair: function () {
        return native.mlKem768Keygen();
    },
    encaps: function (publicKey) {
        return native.mlKem768Encaps(toBuffer(publicKey));
    },
    decaps: function (ciphertext, secretKey) {
        return native.mlKem768Decaps(toBuffer(ciphertext), toBuffer(secretKey));
    }
});

/**
 * NIST FIPS 203 ML-KEM-1024
 */
const mlKem1024 = Object.freeze({
    keypair: function () {
        return native.mlKem1024Keygen();
    },
    encaps: function (publicKey) {
        return native.mlKem1024Encaps(toBuffer(publicKey));
    },
    decaps: function (ciphertext, secretKey) {
        return native.mlKem1024Decaps(toBuffer(ciphertext), toBuffer(secretKey));
    }
});

/**
 * NIST FIPS 204 ML-DSA-65
 */
const mlDsa65 = Object.freeze({
    keypair: function () {
        return native.mlDsa65Keygen();
    },
    sign: function (message, secretKey) {
        return native.mlDsa65Sign(toBuffer(message), toBuffer(secretKey));
    },
    verify: function (signature, message, publicKey) {
        return native.mlDsa65Verify(toBuffer(signature), toBuffer(message), toBuffer(publicKey));
    }
});

/**
 * NIST FIPS 204 ML-DSA-87
 */
const mlDsa87 = Object.freeze({
    keypair: function () {
        return native.mlDsa87Keygen();
    },
    sign: function (message, secretKey) {
        return native.mlDsa87Sign(toBuffer(message), toBuffer(secretKey));
    },
    verify: function (signature, message, publicKey) {
        return native.mlDsa87Verify(toBuffer(signature), toBuffer(message), toBuffer(publicKey));
    }
});

/**
 * SHA-3 & SHAKE XOF
 */
const sha3 = Object.freeze({
    sha3_256: function (data) {
        return native.sha3_256(toBuffer(data));
    },
    sha3_512: function (data) {
        return native.sha3_512(toBuffer(data));
    },
    shake128: function (data, outputLength) {
        if (typeof outputLength !== 'number' || outputLength <= 0) {
            throw new TypeError('outputLength must be a positive integer');
        }
        return native.shake128(toBuffer(data), outputLength);
    },
    shake256: function (data, outputLength) {
        if (typeof outputLength !== 'number' || outputLength <= 0) {
            throw new TypeError('outputLength must be a positive integer');
        }
        return native.shake256(toBuffer(data), outputLength);
    }
});

/**
 * AES-128/256-GCM AEAD
 */
const aesGcm = Object.freeze({
    encrypt128: function (key, iv, plaintext, aad = null) {
        return native.aes128GcmEncrypt(
            toBuffer(key),
            toBuffer(iv),
            toBuffer(plaintext),
            aad ? toBuffer(aad) : null
        );
    },
    decrypt128: function (key, iv, ciphertext, tag, aad = null) {
        return native.aes128GcmDecrypt(
            toBuffer(key),
            toBuffer(iv),
            toBuffer(ciphertext),
            toBuffer(tag),
            aad ? toBuffer(aad) : null
        );
    },
    encrypt256: function (key, iv, plaintext, aad = null) {
        return native.aes256GcmEncrypt(
            toBuffer(key),
            toBuffer(iv),
            toBuffer(plaintext),
            aad ? toBuffer(aad) : null
        );
    },
    decrypt256: function (key, iv, ciphertext, tag, aad = null) {
        return native.aes256GcmDecrypt(
            toBuffer(key),
            toBuffer(iv),
            toBuffer(ciphertext),
            toBuffer(tag),
            aad ? toBuffer(aad) : null
        );
    }
});

/**
 * Cryptographic & Memory Utilities
 */
const utils = Object.freeze({
    cleanse: function (buffer) {
        if (Buffer.isBuffer(buffer)) {
            native.cleanse(buffer);
        } else if (buffer instanceof Uint8Array) {
            native.cleanse(Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength));
        }
    },
    randombytes: function (length) {
        if (typeof length !== 'number' || length < 0) {
            throw new TypeError('length must be a non-negative integer');
        }
        return native.randombytes(length);
    },
    ctMemcmp: function (a, b) {
        return native.ctMemcmp(toBuffer(a), toBuffer(b));
    },
    getSimdCaps: function () {
        return native.getSimdCaps();
    },
    version: function () {
        return native.version();
    }
});

module.exports = {
    constants,
    mlKem768,
    mlKem1024,
    mlDsa65,
    mlDsa87,
    sha3,
    aesGcm,
    utils,
    // Direct convenience bindings
    version: utils.version,
    cleanse: utils.cleanse,
    randombytes: utils.randombytes,
    ctMemcmp: utils.ctMemcmp,
    getSimdCaps: utils.getSimdCaps
};
