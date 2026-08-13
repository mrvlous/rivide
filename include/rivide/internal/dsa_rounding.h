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
 * @file dsa_rounding.h
 * @brief Internal ML-DSA rounding and hint function declarations.
 *
 * Provides exact high/low coefficient decomposition algorithms (Power2Round,
 * Decompose) as well as hint vector generation and application routines.
 */

#ifndef RIVIDE_INTERNAL_DSA_ROUNDING_H
#define RIVIDE_INTERNAL_DSA_ROUNDING_H

#include <stdint.h>

/**
 * @brief Power2Round: decompose t into (t1, t0) where t = t1 * 2^d + t0.
 *
 * @param[in]  a  Coefficient in [0, q-1].
 * @param[out] a0 Pointer to store low bits t0 in [-(2^(d-1)), 2^(d-1)].
 * @return High bits t1 = (t - t0) / 2^d.
 */
int32_t dsa_power2round(int32_t a, int32_t *a0);

/**
 * @brief Decompose: decompose a into (a1, a0) where a = a1 * 2*gamma2 + a0.
 *
 * @param[in]  a      Coefficient in [0, q-1].
 * @param[out] a0     Pointer to store low part in (-gamma2, gamma2].
 * @param[in]  gamma2 Decomposition parameter ((q-1)/32 or (q-1)/88).
 * @return High part a1.
 */
int32_t dsa_decompose(int32_t a, int32_t *a0, int32_t gamma2);

/**
 * @brief Compute the hint bit for one coefficient.
 *
 * @param[in] a0     Low part from Decompose.
 * @param[in] a1     High part from Decompose.
 * @param[in] gamma2 Decomposition parameter.
 * @return 1 if a hint bit is required, or 0 otherwise.
 */
unsigned int dsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2);

/**
 * @brief Apply the hint bit to recover the correct high bits.
 *
 * @param[in] a      Original coefficient.
 * @param[in] hint   Hint bit (0 or 1).
 * @param[in] gamma2 Decomposition parameter.
 * @return Corrected high bits a1.
 */
int32_t dsa_use_hint(int32_t a, unsigned int hint, int32_t gamma2);

#endif /* RIVIDE_INTERNAL_DSA_ROUNDING_H */
