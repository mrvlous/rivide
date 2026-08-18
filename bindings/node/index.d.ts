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

/**
 * Binary input type accepted by Rivide functions.
 */
export type BinaryInput = Buffer | Uint8Array | string;

/**
 * Key encapsulation mechanism keypair.
 */
export interface KemKeyPair {
    publicKey: Buffer;
    secretKey: Buffer;
}

/**
 * Result of KEM encapsulation.
 */
export interface KemEncapsResult {
    ciphertext: Buffer;
    sharedSecret: Buffer;
}

/**
 * Digital signature keypair.
 */
export interface DsaKeyPair {
    publicKey: Buffer;
    secretKey: Buffer;
}

/**
 * Result of AES-GCM AEAD encryption.
 */
export interface AesGcmResult {
    ciphertext: Buffer;
    tag: Buffer;
}

/**
 * Runtime CPU acceleration hardware capabilities.
 */
export interface SimdCapabilities {
    hasAesni: boolean;
    hasArmCrypto: boolean;
    hasAvx2: boolean;
    hasNeon: boolean;
    bitmask: number;
}

/**
 * Buffer size constants according to NIST standards.
 */
export namespace constants {
    export const ML_KEM_768_PK_BYTES: 1184;
    export const ML_KEM_768_SK_BYTES: 2400;
    export const ML_KEM_768_CT_BYTES: 1088;
    export const ML_KEM_768_SS_BYTES: 32;

    export const ML_KEM_1024_PK_BYTES: 1568;
    export const ML_KEM_1024_SK_BYTES: 3168;
    export const ML_KEM_1024_CT_BYTES: 1568;
    export const ML_KEM_1024_SS_BYTES: 32;

    export const ML_DSA_65_PK_BYTES: 1952;
    export const ML_DSA_65_SK_BYTES: 4032;
    export const ML_DSA_65_SIG_BYTES: 3309;

    export const ML_DSA_87_PK_BYTES: 2592;
    export const ML_DSA_87_SK_BYTES: 4896;
    export const ML_DSA_87_SIG_BYTES: 4627;

    export const SHA3_256_BYTES: 32;
    export const SHA3_512_BYTES: 64;
    export const AES_GCM_IV_BYTES: 12;
    export const AES_GCM_TAG_BYTES: 16;
}

/**
 * NIST FIPS 203 ML-KEM-768 (Category 3 / AES-192 equivalent).
 */
export namespace mlKem768 {
    /**
     * Generate a new ML-KEM-768 keypair.
     */
    export function keypair(): KemKeyPair;

    /**
     * Encapsulate a 32-byte shared secret under a public key.
     * @param publicKey 1184-byte public key
     */
    export function encaps(publicKey: BinaryInput): KemEncapsResult;

    /**
     * Decapsulate a shared secret from a ciphertext using a secret key.
     * @param ciphertext 1088-byte ciphertext
     * @param secretKey 2400-byte secret key
     */
    export function decaps(ciphertext: BinaryInput, secretKey: BinaryInput): Buffer;
}

/**
 * NIST FIPS 203 ML-KEM-1024 (Category 5 / AES-256 equivalent).
 */
export namespace mlKem1024 {
    /**
     * Generate a new ML-KEM-1024 keypair.
     */
    export function keypair(): KemKeyPair;

    /**
     * Encapsulate a 32-byte shared secret under a public key.
     * @param publicKey 1568-byte public key
     */
    export function encaps(publicKey: BinaryInput): KemEncapsResult;

    /**
     * Decapsulate a shared secret from a ciphertext using a secret key.
     * @param ciphertext 1568-byte ciphertext
     * @param secretKey 3168-byte secret key
     */
    export function decaps(ciphertext: BinaryInput, secretKey: BinaryInput): Buffer;
}

/**
 * NIST FIPS 204 ML-DSA-65 (Category 3 / AES-192 equivalent).
 */
export namespace mlDsa65 {
    /**
     * Generate a new ML-DSA-65 signature keypair.
     */
    export function keypair(): DsaKeyPair;

    /**
     * Sign an arbitrary-length message using a secret key.
     * @param message Message payload
     * @param secretKey 4032-byte secret key
     */
    export function sign(message: BinaryInput, secretKey: BinaryInput): Buffer;

    /**
     * Verify a digital signature against a message and public key.
     * @param signature 3309-byte signature
     * @param message Message payload
     * @param publicKey 1952-byte public key
     */
    export function verify(
        signature: BinaryInput,
        message: BinaryInput,
        publicKey: BinaryInput
    ): boolean;
}

/**
 * NIST FIPS 204 ML-DSA-87 (Category 5 / AES-256 equivalent).
 */
export namespace mlDsa87 {
    /**
     * Generate a new ML-DSA-87 signature keypair.
     */
    export function keypair(): DsaKeyPair;

    /**
     * Sign an arbitrary-length message using a secret key.
     * @param message Message payload
     * @param secretKey 4896-byte secret key
     */
    export function sign(message: BinaryInput, secretKey: BinaryInput): Buffer;

    /**
     * Verify a digital signature against a message and public key.
     * @param signature 4627-byte signature
     * @param message Message payload
     * @param publicKey 2592-byte public key
     */
    export function verify(
        signature: BinaryInput,
        message: BinaryInput,
        publicKey: BinaryInput
    ): boolean;
}

/**
 * NIST FIPS 202 SHA-3 and SHAKE Extendable-Output Functions.
 */
export namespace sha3 {
    /**
     * Compute 256-bit SHA3 hash (32 bytes).
     */
    export function sha3_256(data: BinaryInput): Buffer;

    /**
     * Compute 512-bit SHA3 hash (64 bytes).
     */
    export function sha3_512(data: BinaryInput): Buffer;

    /**
     * Compute SHAKE-128 extendable-output hash.
     * @param data Input data
     * @param outputLength Desired output length in bytes
     */
    export function shake128(data: BinaryInput, outputLength: number): Buffer;

    /**
     * Compute SHAKE-256 extendable-output hash.
     * @param data Input data
     * @param outputLength Desired output length in bytes
     */
    export function shake256(data: BinaryInput, outputLength: number): Buffer;
}

/**
 * NIST SP 800-38D AES-GCM Authenticated Encryption with Associated Data (AEAD).
 */
export namespace aesGcm {
    /**
     * Encrypt plaintext using AES-128-GCM.
     * @param key 16-byte symmetric key
     * @param iv 12-byte initialization vector
     * @param plaintext Data to encrypt
     * @param aad Optional additional authenticated data
     */
    export function encrypt128(
        key: BinaryInput,
        iv: BinaryInput,
        plaintext: BinaryInput,
        aad?: BinaryInput | null
    ): AesGcmResult;

    /**
     * Decrypt and authenticate ciphertext using AES-128-GCM.
     * @param key 16-byte symmetric key
     * @param iv 12-byte initialization vector
     * @param ciphertext Data to decrypt
     * @param tag 16-byte authentication tag
     * @param aad Optional additional authenticated data
     */
    export function decrypt128(
        key: BinaryInput,
        iv: BinaryInput,
        ciphertext: BinaryInput,
        tag: BinaryInput,
        aad?: BinaryInput | null
    ): Buffer;

    /**
     * Encrypt plaintext using AES-256-GCM.
     * @param key 32-byte symmetric key
     * @param iv 12-byte initialization vector
     * @param plaintext Data to encrypt
     * @param aad Optional additional authenticated data
     */
    export function encrypt256(
        key: BinaryInput,
        iv: BinaryInput,
        plaintext: BinaryInput,
        aad?: BinaryInput | null
    ): AesGcmResult;

    /**
     * Decrypt and authenticate ciphertext using AES-256-GCM.
     * @param key 32-byte symmetric key
     * @param iv 12-byte initialization vector
     * @param ciphertext Data to decrypt
     * @param tag 16-byte authentication tag
     * @param aad Optional additional authenticated data
     */
    export function decrypt256(
        key: BinaryInput,
        iv: BinaryInput,
        ciphertext: BinaryInput,
        tag: BinaryInput,
        aad?: BinaryInput | null
    ): Buffer;
}

/**
 * Cryptographic & Memory Security Utilities.
 */
export namespace utils {
    /**
     * Securely zeroize sensitive buffer in RAM preventing compiler dead-store optimization.
     */
    export function cleanse(buffer: Buffer | Uint8Array): void;

    /**
     * Query OS CSPRNG for cryptographically secure random bytes.
     * @param length Number of bytes to generate
     */
    export function randombytes(length: number): Buffer;

    /**
     * Constant-time byte array comparison (0 if equal, non-zero if different).
     */
    export function ctMemcmp(a: BinaryInput, b: BinaryInput): number;

    /**
     * Query detected runtime CPU SIMD and hardware acceleration capabilities.
     */
    export function getSimdCaps(): SimdCapabilities;

    /**
     * Return the library version string (e.g. "1.1.5").
     */
    export function version(): string;
}

export function version(): string;
export function cleanse(buffer: Buffer | Uint8Array): void;
export function randombytes(length: number): Buffer;
export function ctMemcmp(a: BinaryInput, b: BinaryInput): number;
export function getSimdCaps(): SimdCapabilities;

declare const rivide: {
    constants: typeof constants;
    mlKem768: typeof mlKem768;
    mlKem1024: typeof mlKem1024;
    mlDsa65: typeof mlDsa65;
    mlDsa87: typeof mlDsa87;
    sha3: typeof sha3;
    aesGcm: typeof aesGcm;
    utils: typeof utils;
    version: typeof utils.version;
    cleanse: typeof utils.cleanse;
    randombytes: typeof utils.randombytes;
    ctMemcmp: typeof utils.ctMemcmp;
    getSimdCaps: typeof utils.getSimdCaps;
};

export default rivide;
