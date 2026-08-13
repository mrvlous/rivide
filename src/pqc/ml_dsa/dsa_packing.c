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
 * @file dsa_packing.c
 * @brief ML-DSA polynomial and key packing/unpacking implementation.
 *
 * Handles bit-packing serialization and deserialization of t1, eta-bounded, z,
 * hint polynomials, as well as full public key and secret key structures.
 */

#include "rivide/internal/dsa_packing.h"

#include "rivide/internal/dsa_poly.h"

/**
 * @brief Pack t1 polynomial (10 bits per coefficient) into byte buffer.
 *
 * @param[out] buf Output byte buffer (320 bytes).
 * @param[in]  p   Polynomial with coefficients in [0, 2^10 - 1].
 */
void dsa_poly_pack_t1(uint8_t *buf, const dsa_poly_t *p) {
    unsigned int i;
    for (i = 0; i < DSA_N / 4; i++) {
        buf[5 * i] = (uint8_t)(p->coeffs[4 * i] & 0xFF);
        buf[5 * i + 1] = (uint8_t)((p->coeffs[4 * i] >> 8) | ((p->coeffs[4 * i + 1] & 0x3F) << 2));
        buf[5 * i + 2] =
            (uint8_t)((p->coeffs[4 * i + 1] >> 6) | ((p->coeffs[4 * i + 2] & 0x0F) << 4));
        buf[5 * i + 3] =
            (uint8_t)((p->coeffs[4 * i + 2] >> 4) | ((p->coeffs[4 * i + 3] & 0x03) << 6));
        buf[5 * i + 4] = (uint8_t)(p->coeffs[4 * i + 3] >> 2);
    }
}

/**
 * @brief Unpack t1 polynomial from byte buffer.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer (320 bytes).
 */
void dsa_poly_unpack_t1(dsa_poly_t *p, const uint8_t *buf) {
    unsigned int i;
    for (i = 0; i < DSA_N / 4; i++) {
        p->coeffs[4 * i] = ((uint32_t)buf[5 * i] | ((uint32_t)buf[5 * i + 1] << 8)) & 0x3FF;
        p->coeffs[4 * i + 1] =
            (((uint32_t)buf[5 * i + 1] >> 2) | ((uint32_t)buf[5 * i + 2] << 6)) & 0x3FF;
        p->coeffs[4 * i + 2] =
            (((uint32_t)buf[5 * i + 2] >> 4) | ((uint32_t)buf[5 * i + 3] << 4)) & 0x3FF;
        p->coeffs[4 * i + 3] =
            (((uint32_t)buf[5 * i + 3] >> 6) | ((uint32_t)buf[5 * i + 4] << 2)) & 0x3FF;
    }
}

/**
 * @brief Pack an eta-bounded polynomial into byte buffer.
 *
 * @param[out] buf Output byte buffer.
 * @param[in]  p   Polynomial with coefficients in [-eta, eta].
 * @param[in]  eta Bound parameter (2 for ML-DSA-87, 4 for ML-DSA-65).
 */
void dsa_poly_pack_eta(uint8_t *buf, const dsa_poly_t *p, int eta) {
    unsigned int i;

    if (eta == 2) {
        for (i = 0; i < DSA_N / 8; i++) {
            uint8_t t[8];
            unsigned int j;
            for (j = 0; j < 8; j++) {
                t[j] = (uint8_t)(eta - p->coeffs[8 * i + j]);
            }
            buf[3 * i] = (uint8_t)(t[0] | (t[1] << 3) | (t[2] << 6));
            buf[3 * i + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
            buf[3 * i + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
        }
    } else {
        /* eta == 4 */
        for (i = 0; i < DSA_N / 2; i++) {
            uint8_t t0 = (uint8_t)(eta - p->coeffs[2 * i]);
            uint8_t t1 = (uint8_t)(eta - p->coeffs[2 * i + 1]);
            buf[i] = (uint8_t)(t0 | (t1 << 4));
        }
    }
}

/**
 * @brief Unpack an eta-bounded polynomial from byte buffer.
 *
 * @param[out] p   Output polynomial structure.
 * @param[in]  buf Input byte buffer.
 * @param[in]  eta Bound parameter (2 for ML-DSA-87, 4 for ML-DSA-65).
 */
void dsa_poly_unpack_eta(dsa_poly_t *p, const uint8_t *buf, int eta) {
    unsigned int i;

    if (eta == 2) {
        for (i = 0; i < DSA_N / 8; i++) {
            p->coeffs[8 * i] = (int32_t)(buf[3 * i] & 0x07);
            p->coeffs[8 * i + 1] = (int32_t)((buf[3 * i] >> 3) & 0x07);
            p->coeffs[8 * i + 2] = (int32_t)(((buf[3 * i] >> 6) | (buf[3 * i + 1] << 2)) & 0x07);
            p->coeffs[8 * i + 3] = (int32_t)((buf[3 * i + 1] >> 1) & 0x07);
            p->coeffs[8 * i + 4] = (int32_t)((buf[3 * i + 1] >> 4) & 0x07);
            p->coeffs[8 * i + 5] =
                (int32_t)(((buf[3 * i + 1] >> 7) | (buf[3 * i + 2] << 1)) & 0x07);
            p->coeffs[8 * i + 6] = (int32_t)((buf[3 * i + 2] >> 2) & 0x07);
            p->coeffs[8 * i + 7] = (int32_t)((buf[3 * i + 2] >> 5) & 0x07);

            {
                unsigned int j;
                for (j = 0; j < 8; j++) {
                    p->coeffs[8 * i + j] = eta - p->coeffs[8 * i + j];
                }
            }
        }
    } else {
        for (i = 0; i < DSA_N / 2; i++) {
            p->coeffs[2 * i] = (int32_t)(eta - (buf[i] & 0x0F));
            p->coeffs[2 * i + 1] = (int32_t)(eta - (buf[i] >> 4));
        }
    }
}

/**
 * @brief Pack a gamma1-bounded polynomial into byte buffer.
 *
 * @param[out] buf    Output byte buffer.
 * @param[in]  p      Polynomial with coefficients in [-gamma1+1, gamma1].
 * @param[in]  gamma1 Masking bound (2^17 or 2^19).
 */
void dsa_poly_pack_z(uint8_t *buf, const dsa_poly_t *p, int32_t gamma1) {
    unsigned int i;
    uint32_t t[4];

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < DSA_N / 4; i++) {
            t[0] = (uint32_t)(gamma1 - p->coeffs[4 * i]);
            t[1] = (uint32_t)(gamma1 - p->coeffs[4 * i + 1]);
            t[2] = (uint32_t)(gamma1 - p->coeffs[4 * i + 2]);
            t[3] = (uint32_t)(gamma1 - p->coeffs[4 * i + 3]);

            buf[9 * i] = (uint8_t)(t[0]);
            buf[9 * i + 1] = (uint8_t)(t[0] >> 8);
            buf[9 * i + 2] = (uint8_t)((t[0] >> 16) | (t[1] << 2));
            buf[9 * i + 3] = (uint8_t)(t[1] >> 6);
            buf[9 * i + 4] = (uint8_t)((t[1] >> 14) | (t[2] << 4));
            buf[9 * i + 5] = (uint8_t)(t[2] >> 4);
            buf[9 * i + 6] = (uint8_t)((t[2] >> 12) | (t[3] << 6));
            buf[9 * i + 7] = (uint8_t)(t[3] >> 2);
            buf[9 * i + 8] = (uint8_t)(t[3] >> 10);
        }
    } else {
        /* gamma1 = 2^19 */
        for (i = 0; i < DSA_N / 2; i++) {
            t[0] = (uint32_t)(gamma1 - p->coeffs[2 * i]);
            t[1] = (uint32_t)(gamma1 - p->coeffs[2 * i + 1]);

            buf[5 * i] = (uint8_t)(t[0]);
            buf[5 * i + 1] = (uint8_t)(t[0] >> 8);
            buf[5 * i + 2] = (uint8_t)((t[0] >> 16) | (t[1] << 4));
            buf[5 * i + 3] = (uint8_t)(t[1] >> 4);
            buf[5 * i + 4] = (uint8_t)(t[1] >> 12);
        }
    }
}

/**
 * @brief Unpack a z polynomial from byte buffer.
 *
 * @param[out] p      Output polynomial structure.
 * @param[in]  buf    Input byte buffer.
 * @param[in]  gamma1 Masking bound (2^17 or 2^19).
 */
void dsa_poly_unpack_z(dsa_poly_t *p, const uint8_t *buf, int32_t gamma1) {
    unsigned int i;

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < DSA_N / 4; i++) {
            p->coeffs[4 * i] = (int32_t)(((uint32_t)buf[9 * i] | ((uint32_t)buf[9 * i + 1] << 8) |
                                          ((uint32_t)buf[9 * i + 2] << 16)) &
                                         0x3FFFF);
            p->coeffs[4 * i + 1] =
                (int32_t)((((uint32_t)buf[9 * i + 2] >> 2) | ((uint32_t)buf[9 * i + 3] << 6) |
                           ((uint32_t)buf[9 * i + 4] << 14)) &
                          0x3FFFF);
            p->coeffs[4 * i + 2] =
                (int32_t)((((uint32_t)buf[9 * i + 4] >> 4) | ((uint32_t)buf[9 * i + 5] << 4) |
                           ((uint32_t)buf[9 * i + 6] << 12)) &
                          0x3FFFF);
            p->coeffs[4 * i + 3] =
                (int32_t)((((uint32_t)buf[9 * i + 6] >> 6) | ((uint32_t)buf[9 * i + 7] << 2) |
                           ((uint32_t)buf[9 * i + 8] << 10)) &
                          0x3FFFF);

            {
                unsigned int j;
                for (j = 0; j < 4; j++) {
                    p->coeffs[4 * i + j] = gamma1 - p->coeffs[4 * i + j];
                }
            }
        }
    } else {
        for (i = 0; i < DSA_N / 2; i++) {
            p->coeffs[2 * i] = (int32_t)(((uint32_t)buf[5 * i] | ((uint32_t)buf[5 * i + 1] << 8) |
                                          ((uint32_t)buf[5 * i + 2] << 16)) &
                                         0xFFFFF);
            p->coeffs[2 * i + 1] =
                (int32_t)((((uint32_t)buf[5 * i + 2] >> 4) | ((uint32_t)buf[5 * i + 3] << 4) |
                           ((uint32_t)buf[5 * i + 4] << 12)) &
                          0xFFFFF);

            p->coeffs[2 * i] = gamma1 - p->coeffs[2 * i];
            p->coeffs[2 * i + 1] = gamma1 - p->coeffs[2 * i + 1];
        }
    }
}

/**
 * @brief Pack ML-DSA public key: rho || t1.
 *
 * @param[out] pk  Output public key buffer.
 * @param[in]  rho 32-byte seed for ExpandA matrix generation.
 * @param[in]  t1  High bits polynomial vector t1.
 * @param[in]  k   Module row dimension.
 */
void dsa_pack_pk(uint8_t *pk, const uint8_t rho[32], const dsa_polyveck_t *t1, int k) {
    unsigned int i;
    for (i = 0; i < 32; i++) {
        pk[i] = rho[i];
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_pack_t1(pk + 32 + 320 * i, &t1->vec[i]);
    }
}

/**
 * @brief Unpack ML-DSA public key into rho and t1 components.
 *
 * @param[out] rho Output 32-byte seed buffer.
 * @param[out] t1  Output high bits polynomial vector.
 * @param[in]  pk  Input public key buffer.
 * @param[in]  k   Module row dimension.
 */
void dsa_unpack_pk(uint8_t rho[32], dsa_polyveck_t *t1, const uint8_t *pk, int k) {
    unsigned int i;
    for (i = 0; i < 32; i++) {
        rho[i] = pk[i];
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_unpack_t1(&t1->vec[i], pk + 32 + 320 * i);
    }
}

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
                 int k, int l, int eta) {
    unsigned int i;
    size_t offset = 0;
    size_t eta_bytes = (eta == 2) ? 96 : 128; /* per polynomial */

    for (i = 0; i < 32; i++)
        sk[offset++] = rho[i];
    for (i = 0; i < 32; i++)
        sk[offset++] = K[i];
    for (i = 0; i < 64; i++)
        sk[offset++] = tr[i];

    for (i = 0; i < (unsigned int)l; i++) {
        dsa_poly_pack_eta(sk + offset, &s1->vec[i], eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_pack_eta(sk + offset, &s2->vec[i], eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        /* t0 packing: coefficients in [-(2^12), 2^12], packed as 13 bits
         * each, 8 coefficients per 13 bytes (416 bytes per polynomial). */
        unsigned int j;
        for (j = 0; j < DSA_N / 8; j++) {
            uint32_t t[8];
            unsigned int m;
            for (m = 0; m < 8; m++) {
                t[m] = (uint32_t)((1 << (DSA_D_BITS - 1)) - t0->vec[i].coeffs[8 * j + m]);
            }
            sk[offset + 13 * j + 0] = (uint8_t)(t[0]);
            sk[offset + 13 * j + 1] = (uint8_t)(t[0] >> 8);
            sk[offset + 13 * j + 1] |= (uint8_t)(t[1] << 5);
            sk[offset + 13 * j + 2] = (uint8_t)(t[1] >> 3);
            sk[offset + 13 * j + 3] = (uint8_t)(t[1] >> 11);
            sk[offset + 13 * j + 3] |= (uint8_t)(t[2] << 2);
            sk[offset + 13 * j + 4] = (uint8_t)(t[2] >> 6);
            sk[offset + 13 * j + 4] |= (uint8_t)(t[3] << 7);
            sk[offset + 13 * j + 5] = (uint8_t)(t[3] >> 1);
            sk[offset + 13 * j + 6] = (uint8_t)(t[3] >> 9);
            sk[offset + 13 * j + 6] |= (uint8_t)(t[4] << 4);
            sk[offset + 13 * j + 7] = (uint8_t)(t[4] >> 4);
            sk[offset + 13 * j + 8] = (uint8_t)(t[4] >> 12);
            sk[offset + 13 * j + 8] |= (uint8_t)(t[5] << 1);
            sk[offset + 13 * j + 9] = (uint8_t)(t[5] >> 7);
            sk[offset + 13 * j + 9] |= (uint8_t)(t[6] << 6);
            sk[offset + 13 * j + 10] = (uint8_t)(t[6] >> 2);
            sk[offset + 13 * j + 11] = (uint8_t)(t[6] >> 10);
            sk[offset + 13 * j + 11] |= (uint8_t)(t[7] << 3);
            sk[offset + 13 * j + 12] = (uint8_t)(t[7] >> 5);
        }
        offset += 416;
    }
}

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
                   int eta) {
    unsigned int i;
    size_t offset = 0;
    size_t eta_bytes = (eta == 2) ? 96 : 128;

    for (i = 0; i < 32; i++)
        rho[i] = sk[offset++];
    for (i = 0; i < 32; i++)
        K[i] = sk[offset++];
    for (i = 0; i < 64; i++)
        tr[i] = sk[offset++];

    for (i = 0; i < (unsigned int)l; i++) {
        dsa_poly_unpack_eta(&s1->vec[i], sk + offset, eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        dsa_poly_unpack_eta(&s2->vec[i], sk + offset, eta);
        offset += eta_bytes;
    }
    for (i = 0; i < (unsigned int)k; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N / 8; j++) {
            const uint8_t *a = sk + offset + 13 * j;
            uint32_t t0v = (uint32_t)a[0] | ((uint32_t)a[1] << 8);
            uint32_t t1v = ((uint32_t)a[1] >> 5) | ((uint32_t)a[2] << 3) | ((uint32_t)a[3] << 11);
            uint32_t t2v = ((uint32_t)a[3] >> 2) | ((uint32_t)a[4] << 6);
            uint32_t t3v = ((uint32_t)a[4] >> 7) | ((uint32_t)a[5] << 1) | ((uint32_t)a[6] << 9);
            uint32_t t4v = ((uint32_t)a[6] >> 4) | ((uint32_t)a[7] << 4) | ((uint32_t)a[8] << 12);
            uint32_t t5v = ((uint32_t)a[8] >> 1) | ((uint32_t)a[9] << 7);
            uint32_t t6v = ((uint32_t)a[9] >> 6) | ((uint32_t)a[10] << 2) | ((uint32_t)a[11] << 10);
            uint32_t t7v = ((uint32_t)a[11] >> 3) | ((uint32_t)a[12] << 5);
            t0->vec[i].coeffs[8 * j + 0] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t0v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 1] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t1v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 2] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t2v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 3] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t3v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 4] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t4v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 5] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t5v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 6] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t6v & 0x1FFF));
            t0->vec[i].coeffs[8 * j + 7] = (int32_t)((1 << (DSA_D_BITS - 1)) - (t7v & 0x1FFF));
        }
        offset += 416;
    }
}

/**
 * @brief Pack hint vector h into signature bytes.
 *
 * @param[out] buf   Output signature buffer.
 * @param[in]  h     Hint polynomial vector.
 * @param[in]  k     Module row dimension.
 * @param[in]  omega Maximum number of non-zero hints allowed.
 * @return Number of hint bytes packed.
 */
size_t dsa_pack_hint(uint8_t *buf, const dsa_polyveck_t *h, int k, int omega) {
    unsigned int i, j;
    size_t idx = 0;

    for (i = 0; i < (unsigned int)omega + (unsigned int)k; i++) {
        buf[i] = 0;
    }

    idx = 0;
    for (i = 0; i < (unsigned int)k; i++) {
        for (j = 0; j < DSA_N; j++) {
            if (h->vec[i].coeffs[j] != 0) {
                buf[idx++] = (uint8_t)j;
            }
        }
        buf[(unsigned int)omega + i] = (uint8_t)idx;
    }

    return (size_t)omega + (size_t)k;
}

/**
 * @brief Unpack hint vector h from signature bytes.
 *
 * @param[out] h     Output hint polynomial vector.
 * @param[in]  buf   Input signature byte buffer.
 * @param[in]  k     Module row dimension.
 * @param[in]  omega Maximum number of non-zero hints allowed.
 * @return 0 on success, or 1 if hint encoding is invalid.
 */
int dsa_unpack_hint(dsa_polyveck_t *h, const uint8_t *buf, int k, int omega) {
    unsigned int i, j, prev;

    for (i = 0; i < (unsigned int)k; i++) {
        for (j = 0; j < DSA_N; j++) {
            h->vec[i].coeffs[j] = 0;
        }
    }

    prev = 0;
    for (i = 0; i < (unsigned int)k; i++) {
        unsigned int end = (unsigned int)buf[(unsigned int)omega + i];
        if (end < prev || end > (unsigned int)omega) {
            return 1;
        }
        for (j = prev; j < end; j++) {
            if (j > prev && buf[j] <= buf[j - 1]) {
                return 1;
            }
            h->vec[i].coeffs[(unsigned int)buf[j]] = 1;
        }
        prev = end;
    }

    /* Remaining entries in buf must be zero. */
    for (j = prev; j < (unsigned int)omega; j++) {
        if (buf[j] != 0) {
            return 1;
        }
    }

    return 0;
}
