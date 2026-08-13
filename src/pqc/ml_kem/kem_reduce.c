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
 * @file kem_reduce.c
 * @brief ML-KEM Barrett reduction, Montgomery reduction, and conditional subtraction of q.
 *
 * Implements modular reductions modulo q = 3329 used by ML-KEM-768 and ML-KEM-1024
 * (NIST FIPS 203).
 */

#include "rivide/internal/kem_reduce.h"

#include "rivide/internal/kem_poly.h"

/**
 * @brief Barrett reduction: reduce a 16-bit value mod q = 3329.
 *
 * @param[in] a Signed 16-bit coefficient to reduce.
 * @return Reduced coefficient in [0, q-1].
 */
int16_t barrett_reduce(int16_t a) {
    int32_t t;
    /* Barrett constant: floor(2^26 / q) + 1 = 20159 */
    t = ((int32_t)20159 * (int32_t)a + (1 << 25)) >> 26;
    t = (int32_t)a - t * KEM_Q;
    return (int16_t)t;
}

/**
 * @brief Montgomery reduction: compute a * R^{-1} mod q where R = 2^16.
 *
 * @param[in] a 32-bit product to reduce.
 * @return Reduced coefficient.
 */
int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)((uint32_t)(uint16_t)a * (uint32_t)KEM_Q_INV);
    t = (int16_t)((a - (int32_t)t * KEM_Q) >> 16);
    return t;
}

/**
 * @brief Conditionally subtract q if coefficient is >= q.
 *
 * @param[in] a Coefficient in [0, 2q-1].
 * @return Normalized coefficient in [0, q-1].
 */
int16_t cond_sub_q(int16_t a) {
    a += (a >> 15) & KEM_Q;
    a -= KEM_Q;
    a += (a >> 15) & KEM_Q;
    return a;
}
