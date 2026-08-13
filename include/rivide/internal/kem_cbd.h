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
 * @file kem_cbd.h
 * @brief Internal ML-KEM Centered Binomial Distribution (CBD) sampling declarations.
 *
 * Provides functions to sample polynomial coefficients from a Centered Binomial
 * Distribution (CBD_eta) given uniform byte streams.
 */

#ifndef RIVIDE_INTERNAL_KEM_CBD_H
#define RIVIDE_INTERNAL_KEM_CBD_H

#include <stdint.h>

#include "rivide/internal/kem_poly.h"

/**
 * @brief Sample a polynomial from a Centered Binomial Distribution (CBD_eta).
 *
 * @param[out] p   Output polynomial with coefficients in [-eta, eta].
 * @param[in]  buf Input byte stream (64*eta bytes).
 * @param[in]  eta CBD parameter (2 or 3).
 */
void poly_cbd(poly_t *p, const uint8_t *buf, int eta);

#endif /* RIVIDE_INTERNAL_KEM_CBD_H */
