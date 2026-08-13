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
 * @file kem_sampling.h
 * @brief Internal ML-KEM uniform and noise sampling declarations.
 *
 * Provides functions for ExpandA matrix generation via SHAKE-128 rejection
 * sampling and PRF noise sampling via SHAKE-256 and CBD.
 */

#ifndef RIVIDE_INTERNAL_KEM_SAMPLING_H
#define RIVIDE_INTERNAL_KEM_SAMPLING_H

#include <stdint.h>

#include "rivide/internal/kem_poly.h"

/**
 * @brief Sample a uniformly random polynomial from SHAKE-128 (ExpandA).
 *
 * @param[out] p    Output polynomial structure.
 * @param[in]  seed 34-byte seed consisting of rho (32 bytes) and matrix coordinates.
 */
void poly_uniform(poly_t *p, const uint8_t seed[34]);

/**
 * @brief Sample a noise polynomial from SHAKE-256 and CBD (PRF).
 *
 * @param[out] p     Output noise polynomial.
 * @param[in]  seed  32-byte seed (sigma or coins).
 * @param[in]  nonce Nonce byte counter.
 * @param[in]  eta   CBD parameter (2 or 3).
 */
void poly_noise(poly_t *p, const uint8_t seed[32], uint8_t nonce, int eta);

#endif /* RIVIDE_INTERNAL_KEM_SAMPLING_H */
