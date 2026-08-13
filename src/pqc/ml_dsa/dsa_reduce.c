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
 * @file dsa_reduce.c
 * @brief ML-DSA modular arithmetic: Montgomery reduction, centered reduction,
 *        and conditional addition of q.
 *
 * Provides implementations for modular reductions modulo q = 8380417 used by
 * ML-DSA-65 and ML-DSA-87 (NIST FIPS 204).
 */

#include "rivide/internal/dsa_reduce.h"

#include "rivide/internal/dsa_poly.h"

/**
 * @brief Montgomery reduction for Dilithium (32-bit).
 *
 * Given a 64-bit value a, computes a * R^{-1} mod q where R = 2^32.
 *
 * @param[in] a 64-bit value to reduce.
 * @return Reduced coefficient in (-q, q).
 */
int32_t dsa_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((uint32_t)a * (uint32_t)DSA_QINV);
    t = (int32_t)((a - (int64_t)t * DSA_Q) >> 32);
    return t;
}

/**
 * @brief Reduce a coefficient modulo q to the centered range (-q/2, q/2].
 *
 * @param[in] a Coefficient to reduce.
 * @return Centered coefficient in (-q/2, q/2].
 */
int32_t dsa_reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * DSA_Q;
    return t;
}

/**
 * @brief Conditionally add q if coefficient is negative.
 *
 * @param[in] a Coefficient in (-q, q).
 * @return Coefficient normalized to [0, q-1].
 */
int32_t dsa_caddq(int32_t a) {
    a += (a >> 31) & DSA_Q;
    return a;
}
