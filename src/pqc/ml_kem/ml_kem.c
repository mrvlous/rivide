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
 * @file ml_kem.c
 * @brief NIST FIPS 203 ML-KEM public API implementation (Kyber).
 *
 * Implements the complete ML-KEM key encapsulation mechanism:
 * KeyGen, Encapsulation, and Decapsulation with implicit rejection.
 * Parameterized to support both ML-KEM-768 (k=3) and ML-KEM-1024 (k=4).
 */

#include "rivide/pqc/ml_kem.h"

#include "rivide/crypto/sha3.h"
#include "rivide/internal/kem_compress.h"
#include "rivide/internal/kem_encode.h"
#include "rivide/internal/kem_ntt.h"
#include "rivide/internal/kem_packing.h"
#include "rivide/internal/kem_poly.h"
#include "rivide/internal/kem_reduce.h"
#include "rivide/internal/kem_sampling.h"
#include "rivide/pqc/ntt_simd.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

/**
 * @brief Internal K-PKE key generation (Algorithm 12 of FIPS 203).
 */
static void ml_kem_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32], int k,
                                    int eta1) {
    uint8_t buf[64];
    uint8_t g_input[33];
    uint8_t rho[32], sigma[32];
    polyvec_t a_row, s, e, t;
    uint8_t extseed[34];
    int i, j;
    uint8_t nonce = 0;

    for (i = 0; i < 32; i++) {
        g_input[i] = seed[i];
    }
    g_input[32] = (uint8_t)k;
    rivide_sha3_512(buf, g_input, 33);
    for (i = 0; i < 32; i++) {
        rho[i] = buf[i];
        sigma[i] = buf[32 + i];
    }

    for (i = 0; i < k; i++) {
        poly_noise(&s.vec[i], sigma, nonce++, eta1);
    }
    for (i = 0; i < k; i++) {
        poly_noise(&e.vec[i], sigma, nonce++, eta1);
    }

    polyvec_ntt(&s, k);
    polyvec_ntt(&e, k);

    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            unsigned int idx;
            for (idx = 0; idx < 32; idx++) {
                extseed[idx] = rho[idx];
            }
            extseed[32] = (uint8_t)j;
            extseed[33] = (uint8_t)i;
            poly_uniform(&a_row.vec[j], extseed);
        }

        polyvec_pointwise_acc(&t.vec[i], &a_row, &s, k);
        poly_tomont(&t.vec[i]);
        poly_add(&t.vec[i], &t.vec[i], &e.vec[i]);
    }

    for (i = 0; i < k; i++) {
        poly_reduce(&s.vec[i]);
        poly_csubq(&s.vec[i]);
        poly_reduce(&t.vec[i]);
        poly_csubq(&t.vec[i]);
    }

    polyvec_tobytes(pk, &t, k);
    for (i = 0; i < 32; i++) {
        pk[384 * k + i] = rho[i];
    }

    polyvec_tobytes(sk, &s, k);

    rivide_cleanse(buf, sizeof(buf));
    rivide_cleanse(sigma, sizeof(sigma));
    rivide_cleanse(&s, sizeof(s));
    rivide_cleanse(&e, sizeof(e));
}

/**
 * @brief Internal K-PKE encryption (Algorithm 13 of FIPS 203).
 */
static void ml_kem_encrypt_internal(uint8_t *ct, const uint8_t *pk, const uint8_t msg[32],
                                    const uint8_t coins[32], int k, int eta1, int eta2, int du,
                                    int dv) {
    polyvec_t r_vec, e1, at_row, u;
    poly_t e2, v_poly, msg_poly;
    uint8_t rho[32];
    uint8_t extseed[34];
    int i, j;
    uint8_t nonce = 0;
    size_t u_bytes;

    for (i = 0; i < 32; i++) {
        rho[i] = pk[384 * k + i];
    }

    for (i = 0; i < k; i++) {
        poly_noise(&r_vec.vec[i], coins, nonce++, eta1);
    }
    for (i = 0; i < k; i++) {
        poly_noise(&e1.vec[i], coins, nonce++, eta2);
    }

    poly_noise(&e2, coins, nonce++, eta2);

    polyvec_ntt(&r_vec, k);

    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            unsigned int idx;
            for (idx = 0; idx < 32; idx++) {
                extseed[idx] = rho[idx];
            }
            extseed[32] = (uint8_t)i;
            extseed[33] = (uint8_t)j;
            poly_uniform(&at_row.vec[j], extseed);
        }

        polyvec_pointwise_acc(&u.vec[i], &at_row, &r_vec, k);
        poly_invntt(&u.vec[i]);
        poly_add(&u.vec[i], &u.vec[i], &e1.vec[i]);
    }

    {
        polyvec_t t_hat;
        polyvec_frombytes(&t_hat, pk, k);
        polyvec_pointwise_acc(&v_poly, &t_hat, &r_vec, k);
        poly_invntt(&v_poly);
    }

    poly_add(&v_poly, &v_poly, &e2);
    poly_frommsg(&msg_poly, msg);
    poly_add(&v_poly, &v_poly, &msg_poly);

    for (i = 0; i < k; i++) {
        poly_reduce(&u.vec[i]);
        poly_csubq(&u.vec[i]);
    }
    poly_reduce(&v_poly);
    poly_csubq(&v_poly);

    if (du == 10) {
        u_bytes = 320 * (size_t)k;
    } else {
        u_bytes = 352 * (size_t)k;
    }
    polyvec_compress(ct, &u, k, du);
    poly_compress(ct + u_bytes, &v_poly, dv);

    rivide_cleanse(&r_vec, sizeof(r_vec));
    rivide_cleanse(&e1, sizeof(e1));
    rivide_cleanse(&e2, sizeof(e2));
}

/**
 * @brief Internal ML-KEM decryption (K-PKE.Decrypt).
 */
static void ml_kem_decrypt_internal(uint8_t msg[32], const uint8_t *ct, const uint8_t *sk, int k,
                                    int du, int dv) {
    polyvec_t u, s_hat;
    poly_t v_poly, tmp;
    size_t u_bytes;

    if (du == 10) {
        u_bytes = 320 * (size_t)k;
    } else {
        u_bytes = 352 * (size_t)k;
    }

    polyvec_decompress(&u, ct, k, du);
    poly_decompress(&v_poly, ct + u_bytes, dv);

    polyvec_frombytes(&s_hat, sk, k);

    polyvec_ntt(&u, k);
    polyvec_pointwise_acc(&tmp, &s_hat, &u, k);
    poly_invntt(&tmp);

    poly_sub(&v_poly, &v_poly, &tmp);
    poly_reduce(&v_poly);
    poly_csubq(&v_poly);

    poly_tomsg(msg, &v_poly);

    rivide_cleanse(&s_hat, sizeof(s_hat));
    rivide_cleanse(&u, sizeof(u));
    rivide_cleanse(&v_poly, sizeof(v_poly));
    rivide_cleanse(&tmp, sizeof(tmp));
}

/**
 * @brief Full ML-KEM key generation (Algorithm 16 of FIPS 203).
 */
static rivide_status_t ml_kem_keygen(uint8_t *pk, uint8_t *sk, int k, int eta1, size_t pk_bytes,
                                     size_t sk_bytes) {
    uint8_t d[32], z[32];
    rivide_status_t ret;
    size_t s_hat_bytes = 384 * (size_t)k;

    (void)sk_bytes;

    ret = rivide_randombytes(d, 32);
    if (ret != RIVIDE_SUCCESS) {
        return ret;
    }

    ret = rivide_randombytes(z, 32);
    if (ret != RIVIDE_SUCCESS) {
        rivide_cleanse(d, sizeof(d));
        return ret;
    }

    ml_kem_keypair_internal(pk, sk, d, k, eta1);

    {
        size_t offset = s_hat_bytes;
        unsigned int i;

        for (i = 0; i < pk_bytes; i++) {
            sk[offset + i] = pk[i];
        }
        offset += pk_bytes;

        rivide_sha3_256(sk + offset, pk, pk_bytes);
        offset += 32;

        for (i = 0; i < 32; i++) {
            sk[offset + i] = z[i];
        }
    }

    rivide_cleanse(d, sizeof(d));
    rivide_cleanse(z, sizeof(z));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Full ML-KEM encapsulation (Algorithm 17 of FIPS 203).
 */
static rivide_status_t ml_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, int k, int eta1,
                                     int eta2, int du, int dv, size_t pk_bytes) {
    uint8_t m[32], h_pk[32];
    uint8_t g_input[64], g_output[64];
    rivide_status_t ret;
    unsigned int i;

    if (!ct || !ss || !pk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    ret = rivide_randombytes(m, 32);
    if (ret != RIVIDE_SUCCESS) {
        return ret;
    }

    rivide_sha3_256(h_pk, pk, pk_bytes);

    for (i = 0; i < 32; i++) {
        g_input[i] = m[i];
        g_input[32 + i] = h_pk[i];
    }
    rivide_sha3_512(g_output, g_input, 64);

    ml_kem_encrypt_internal(ct, pk, m, g_output + 32, k, eta1, eta2, du, dv);

    for (i = 0; i < 32; i++) {
        ss[i] = g_output[i];
    }

    rivide_cleanse(m, sizeof(m));
    rivide_cleanse(g_input, sizeof(g_input));
    rivide_cleanse(g_output, sizeof(g_output));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Full ML-KEM decapsulation (Algorithm 18 of FIPS 203).
 */
static rivide_status_t ml_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, int k,
                                     int eta1, int eta2, int du, int dv, size_t pk_bytes,
                                     size_t ct_bytes) {
    size_t s_hat_bytes = 384 * (size_t)k;
    const uint8_t *pk = sk + s_hat_bytes;
    const uint8_t *h_pk = pk + pk_bytes;
    const uint8_t *z = h_pk + 32;

    uint8_t m_prime[32];
    uint8_t g_input[64], g_output[64];
    uint8_t ct_prime[1568]; /* Max ciphertext size (ML-KEM-1024). */
    uint8_t k_reject[32];
    unsigned int i;
    int cmp;

    if (!ss || !ct || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    ml_kem_decrypt_internal(m_prime, ct, sk, k, du, dv);

    for (i = 0; i < 32; i++) {
        g_input[i] = m_prime[i];
        g_input[32 + i] = h_pk[i];
    }
    rivide_sha3_512(g_output, g_input, 64);

    ml_kem_encrypt_internal(ct_prime, pk, m_prime, g_output + 32, k, eta1, eta2, du, dv);

    {
        rivide_keccak_state_t jstate;
        rivide_shake256_init(&jstate);
        rivide_shake_absorb(&jstate, z, 32);
        rivide_shake_absorb(&jstate, ct, ct_bytes);
        rivide_shake_squeeze(&jstate, k_reject, 32);
    }

    cmp = rivide_ct_memcmp(ct, ct_prime, ct_bytes);

    rivide_ct_select(ss, g_output, k_reject, 32, cmp);

    rivide_cleanse(m_prime, sizeof(m_prime));
    rivide_cleanse(g_input, sizeof(g_input));
    rivide_cleanse(g_output, sizeof(g_output));
    rivide_cleanse(ct_prime, ct_bytes);
    rivide_cleanse(k_reject, sizeof(k_reject));

    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_ml_kem_768_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }
    return ml_kem_keygen(pk, sk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_PK_BYTES, RIVIDE_ML_KEM_768_SK_BYTES);
}

rivide_status_t rivide_ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return ml_kem_encaps(ct, ss, pk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_ETA2, RIVIDE_ML_KEM_768_DU, RIVIDE_ML_KEM_768_DV,
                         RIVIDE_ML_KEM_768_PK_BYTES);
}

rivide_status_t rivide_ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return ml_kem_decaps(ss, ct, sk, RIVIDE_ML_KEM_768_K, RIVIDE_ML_KEM_768_ETA1,
                         RIVIDE_ML_KEM_768_ETA2, RIVIDE_ML_KEM_768_DU, RIVIDE_ML_KEM_768_DV,
                         RIVIDE_ML_KEM_768_PK_BYTES, RIVIDE_ML_KEM_768_CT_BYTES);
}

rivide_status_t rivide_ml_kem_1024_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }
    return ml_kem_keygen(pk, sk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_PK_BYTES, RIVIDE_ML_KEM_1024_SK_BYTES);
}

rivide_status_t rivide_ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return ml_kem_encaps(ct, ss, pk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_ETA2, RIVIDE_ML_KEM_1024_DU, RIVIDE_ML_KEM_1024_DV,
                         RIVIDE_ML_KEM_1024_PK_BYTES);
}

rivide_status_t rivide_ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return ml_kem_decaps(ss, ct, sk, RIVIDE_ML_KEM_1024_K, RIVIDE_ML_KEM_1024_ETA1,
                         RIVIDE_ML_KEM_1024_ETA2, RIVIDE_ML_KEM_1024_DU, RIVIDE_ML_KEM_1024_DV,
                         RIVIDE_ML_KEM_1024_PK_BYTES, RIVIDE_ML_KEM_1024_CT_BYTES);
}
