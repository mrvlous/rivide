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
 * @file dsa_rounding.c
 * @brief ML-DSA rounding functions: Power2Round, Decompose, MakeHint, UseHint.
 *
 * Implements high/low coefficient decomposition and hint generation algorithms
 * specified in NIST FIPS 204.
 */

#include "rivide/internal/dsa_rounding.h"

#include "rivide/internal/dsa_poly.h"

/**
 * @brief Power2Round: decompose t into (t1, t0) where t = t1 * 2^d + t0.
 *
 * @param[in]  a  Coefficient in [0, q-1].
 * @param[out] a0 Pointer to store low bits t0 in [-(2^(d-1)), 2^(d-1)].
 * @return High bits t1 = (t - t0) / 2^d.
 */
int32_t dsa_power2round(int32_t a, int32_t *a0) {
    int32_t a1;
    a1 = (a + (1 << (DSA_D_BITS - 1)) - 1) >> DSA_D_BITS;
    *a0 = a - (a1 << DSA_D_BITS);
    return a1;
}

/**
 * @brief Decompose: decompose a into (a1, a0) where a = a1 * 2*gamma2 + a0.
 *
 * @param[in]  a      Coefficient in [0, q-1].
 * @param[out] a0     Pointer to store low part in (-gamma2, gamma2].
 * @param[in]  gamma2 Decomposition parameter ((q-1)/32 or (q-1)/88).
 * @return High part a1.
 */
int32_t dsa_decompose(int32_t a, int32_t *a0, int32_t gamma2) {
    int32_t a1;
    a1 = (a + 127) >> 7;

    if (gamma2 == (DSA_Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        /* gamma2 == (Q-1)/88 */
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    *a0 = a - a1 * 2 * gamma2;
    *a0 -= (((DSA_Q - 1) / 2 - *a0) >> 31) & DSA_Q;
    return a1;
}

/**
 * @brief Compute the hint bit for one coefficient.
 *
 * @param[in] a0     Low part from Decompose.
 * @param[in] a1     High part from Decompose.
 * @param[in] gamma2 Decomposition parameter.
 * @return 1 if a hint bit is required, or 0 otherwise.
 */
unsigned int dsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2) {
    if (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Apply the hint bit to recover the correct high bits.
 *
 * @param[in] a      Original coefficient.
 * @param[in] hint   Hint bit (0 or 1).
 * @param[in] gamma2 Decomposition parameter.
 * @return Corrected high bits a1.
 */
int32_t dsa_use_hint(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;

    a1 = dsa_decompose(a, &a0, gamma2);

    if (hint == 0) {
        return a1;
    }

    if (gamma2 == (DSA_Q - 1) / 32) {
        if (a0 > 0) {
            return (a1 + 1) & 15;
        }
        return (a1 - 1) & 15;
    }

    /* gamma2 == (Q-1)/88 */
    if (a0 > 0) {
        return (a1 == 43) ? 0 : a1 + 1;
    }
    return (a1 == 0) ? 43 : a1 - 1;
}
