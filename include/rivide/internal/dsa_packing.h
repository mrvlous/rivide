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
 * @file dsa_packing.h
 * @brief Internal ML-DSA polynomial and key packing/unpacking declarations.
 *
 * Provides functions for bit-packing polynomials (t1, eta, z, hint) as well as
 * full serialization and deserialization of ML-DSA public and secret keys.
 */

#ifndef RIVIDE_INTERNAL_DSA_PACKING_H
#define RIVIDE_INTERNAL_DSA_PACKING_H

#include <stddef.h>
#include <stdint.h>

#include "rivide/internal/dsa_poly.h"

/**
 * @brief Pack t1 polynomial (10 bits per coefficient) into byte buffer.
 *
 * @param[out] buf Output byte buffer (320 bytes).
 * @param[in]  p   Polynomial with coefficients in [0, 2^10 - 1].
 */
void dsa_poly_pack_t1(uint8_t *buf, const dsa_poly_t *p);

/**
 * @brief Unpack t1 polynomial from byte buffer.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer (320 bytes).
 */
void dsa_poly_unpack_t1(dsa_poly_t *p, const uint8_t *buf);

/**
 * @brief Pack an eta-bounded polynomial into byte buffer.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  p   Polynomial with coefficients in [-eta, eta].
 * @param[in]  eta Bound parameter (2 for ML-DSA-87, 4 for ML-DSA-65).
 */
void dsa_poly_pack_eta(uint8_t *buf, const dsa_poly_t *p, int eta);

/**
 * @brief Unpack an eta-bounded polynomial from byte buffer.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  eta Bound parameter (2 for ML-DSA-87, 4 for ML-DSA-65).
 */
void dsa_poly_unpack_eta(dsa_poly_t *p, const uint8_t *buf, int eta);

/**
 * @brief Pack a gamma1-bounded polynomial into byte buffer.
 *
 * @param[out] buf    Output byte buffer.
 * @param[in]  p      Polynomial with coefficients in [-gamma1+1, gamma1].
 * @param[in]  gamma1 Masking bound (2^17 or 2^19).
 */
void dsa_poly_pack_z(uint8_t *buf, const dsa_poly_t *p, int32_t gamma1);

/**
 * @brief Unpack a z polynomial from byte buffer.
 *
 * @param[out] p      Output polynomial structure.
 * @param[in]  buf    Input byte buffer.
 * @param[in]  gamma1 Masking bound (2^17 or 2^19).
 */
void dsa_poly_unpack_z(dsa_poly_t *p, const uint8_t *buf, int32_t gamma1);

/**
 * @brief Pack ML-DSA public key: rho || t1.
 *
 * @param[out] pk  Output public key buffer.
 * @param[in]  rho 32-byte seed for ExpandA matrix generation.
 * @param[in]  t1  High bits polynomial vector t1.
 * @param[in]  k   Module row dimension.
 */
void dsa_pack_pk(uint8_t *pk, const uint8_t rho[32], const dsa_polyveck_t *t1, int k);

/**
 * @brief Unpack ML-DSA public key into rho and t1 components.
 *
 * @param[out] rho Output 32-byte seed buffer.
 * @param[out] t1  Output high bits polynomial vector.
 * @param[in]  pk  Input public key buffer.
 * @param[in]  k   Module row dimension.
 */
void dsa_unpack_pk(uint8_t rho[32], dsa_polyveck_t *t1, const uint8_t *pk, int k);

/**
 * @brief Pack ML-DSA secret key: rho || K || tr || s1 || s2 || t0.
 *
 * @param[out] sk  Output secret key buffer.
 * @param[in]  rho 32-byte seed for ExpandA.
 * @param[in]  tr  64-byte hash of public key.
 * @param[in]  K   32-byte secret key seed for signing.
 * @param[in]  s1  Secret polynomial vector s1.
 * @param[in]  s2  Secret polynomial vector s2.
 * @param[in]  t0  Low bits polynomial vector t0.
 * @param[in]  k   Module row dimension.
 * @param[in]  l   Module column dimension.
 * @param[in]  eta Secret bound parameter.
 */
void dsa_pack_sk(uint8_t *sk, const uint8_t rho[32], const uint8_t tr[64], const uint8_t K[32],
                 const dsa_polyvecl_t *s1, const dsa_polyveck_t *s2, const dsa_polyveck_t *t0,
                 int k, int l, int eta);

/**
 * @brief Unpack ML-DSA secret key into its constituent vectors and seeds.
 *
 * @param[out] rho Output 32-byte seed for ExpandA.
 * @param[out] tr  Output 64-byte public key hash.
 * @param[out] K   Output 32-byte secret seed.
 * @param[out] s1  Output secret polynomial vector s1.
 * @param[out] s2  Output secret polynomial vector s2.
 * @param[out] t0  Output low bits polynomial vector t0.
 * @param[in]  sk  Input secret key buffer.
 * @param[in]  k   Module row dimension.
 * @param[in]  l   Module column dimension.
 * @param[in]  eta Secret bound parameter.
 */
void dsa_unpack_sk(uint8_t rho[32], uint8_t tr[64], uint8_t K[32], dsa_polyvecl_t *s1,
                   dsa_polyveck_t *s2, dsa_polyveck_t *t0, const uint8_t *sk, int k, int l,
                   int eta);

/**
 * @brief Pack hint vector h into signature bytes.
 *
 * @param[out] buf   Output signature buffer.
 * @param[in]  h     Hint polynomial vector.
 * @param[in]  k     Module row dimension.
 * @param[in]  omega Maximum number of non-zero hints allowed.
 * @return Number of hint bytes packed.
 */
size_t dsa_pack_hint(uint8_t *buf, const dsa_polyveck_t *h, int k, int omega);

/**
 * @brief Unpack hint vector h from signature bytes.
 *
 * @param[out] h     Output hint polynomial vector.
 * @param[in]  buf   Input signature byte buffer.
 * @param[in]  k     Module row dimension.
 * @param[in]  omega Maximum number of non-zero hints allowed.
 * @return 0 on success, or 1 if hint encoding is invalid.
 */
int dsa_unpack_hint(dsa_polyveck_t *h, const uint8_t *buf, int k, int omega);

#endif /* RIVIDE_INTERNAL_DSA_PACKING_H */
