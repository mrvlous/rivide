/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 */

import cjsModule from './index.js';

export const {
    constants,
    mlKem768,
    mlKem1024,
    mlDsa65,
    mlDsa87,
    sha3,
    aesGcm,
    utils,
    version,
    cleanse,
    randombytes,
    ctMemcmp,
    getSimdCaps
} = cjsModule;

export default cjsModule;
