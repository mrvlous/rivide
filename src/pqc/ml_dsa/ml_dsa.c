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
 * @file ml_dsa.c
 * @brief NIST FIPS 204 ML-DSA public API: KeyGen, Sign, and Verify.
 *
 * This file contains the high-level ML-DSA operations that compose the
 * modular sub-components (NTT, rounding, packing, sampling) into the
 * complete digital signature scheme with rejection sampling.
 *
 * The implementation is parameterized to support both ML-DSA-65 (k=6, l=5)
 * and ML-DSA-87 (k=8, l=7) from the same codebase.
 */

#include "rivide/pqc/ml_dsa.h"

#include "rivide/crypto/sha3.h"
#include "rivide/internal/dsa_ntt.h"
#include "rivide/internal/dsa_packing.h"
#include "rivide/internal/dsa_poly.h"
#include "rivide/internal/dsa_reduce.h"
#include "rivide/internal/dsa_rounding.h"
#include "rivide/internal/dsa_sampling.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

/**
 * @brief Internal ML-DSA key generation.
 */
static rivide_status_t ml_dsa_keygen_internal(uint8_t *pk, uint8_t *sk, int k, int l, int eta,
                                              int32_t gamma2) {
    uint8_t seed[32], buf[128];
    uint8_t rho[32], rho_prime[64], K[32];
    dsa_polyvecl_t s1, s1_hat;
    dsa_polyveck_t s2, t, t1, t0;
    uint8_t tr[64];
    rivide_status_t ret;
    int i;

    (void)gamma2;

    ret = rivide_randombytes(seed, 32);
    if (ret != RIVIDE_SUCCESS)
        return ret;

    /* H(seed || k || l) -> rho, rho', K */
    {
        uint8_t h_input[34];
        unsigned int j;
        for (j = 0; j < 32; j++)
            h_input[j] = seed[j];
        h_input[32] = (uint8_t)k;
        h_input[33] = (uint8_t)l;
        rivide_shake256(buf, 128, h_input, 34);
    }

    for (i = 0; i < 32; i++)
        rho[i] = buf[i];
    for (i = 0; i < 64; i++)
        rho_prime[i] = buf[32 + i];
    for (i = 0; i < 32; i++)
        K[i] = buf[96 + i];

    /* ExpandS: sample s1, s2. */
    for (i = 0; i < l; i++) {
        dsa_poly_uniform_eta(&s1.vec[i], rho_prime, 64, (uint16_t)i, eta);
    }
    for (i = 0; i < k; i++) {
        dsa_poly_uniform_eta(&s2.vec[i], rho_prime, 64, (uint16_t)(l + i), eta);
    }

    /* s1_hat = NTT(s1) */
    for (i = 0; i < l; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N; j++) {
            s1_hat.vec[i].coeffs[j] = dsa_caddq(s1.vec[i].coeffs[j]);
        }
        dsa_poly_ntt(&s1_hat.vec[i]);
    }

    /* t = A * s1_hat (in NTT domain) */
    dsa_expand_matrix_mul(&t, rho, &s1_hat, k, l);

    /* t = INTT(t) + s2 */
    for (i = 0; i < k; i++) {
        dsa_poly_invntt(&t.vec[i]);
        dsa_poly_add(&t.vec[i], &t.vec[i], &s2.vec[i]);
        dsa_poly_caddq(&t.vec[i]);
    }

    /* Power2Round(t) -> (t1, t0) */
    for (i = 0; i < k; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N; j++) {
            t1.vec[i].coeffs[j] = dsa_power2round(t.vec[i].coeffs[j], &t0.vec[i].coeffs[j]);
        }
    }

    /* Pack public key. */
    dsa_pack_pk(pk, rho, &t1, k);

    /* tr = H(pk) */
    {
        size_t pk_bytes = 32 + 320 * (size_t)k;
        rivide_shake256(tr, 64, pk, pk_bytes);
    }

    /* Pack secret key. */
    dsa_pack_sk(sk, rho, tr, K, &s1, &s2, &t0, k, l, eta);

    /* Cleanse. */
    rivide_cleanse(seed, sizeof(seed));
    rivide_cleanse(buf, sizeof(buf));
    rivide_cleanse(rho_prime, sizeof(rho_prime));
    rivide_cleanse(K, sizeof(K));
    rivide_cleanse(&s1, sizeof(s1));
    rivide_cleanse(&s1_hat, sizeof(s1_hat));
    rivide_cleanse(&s2, sizeof(s2));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Internal ML-DSA signing with rejection sampling.
 */
static rivide_status_t ml_dsa_sign_internal(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                            size_t msglen, const uint8_t *sk, int k, int l, int eta,
                                            int32_t gamma1, int32_t gamma2, unsigned int tau,
                                            int omega, size_t ctilde_bytes) {
    uint8_t rho[32], tr[64], K[32];
    dsa_polyvecl_t s1, y, z;
    dsa_polyveck_t s2, t0, w, w0, w1;
    dsa_polyveck_t cs2, ct0, h;
    dsa_poly_t cp;
    uint8_t mu[64];
    uint8_t rho_prime[64];
    int i, reject;
    unsigned int hint_count;
    uint16_t nonce = 0;
    size_t sig_offset;
    size_t z_bytes_per_poly;

    if (!sig || !siglen || !msg || !sk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    /* Unpack secret key. */
    dsa_unpack_sk(rho, tr, K, &s1, &s2, &t0, sk, k, l, eta);

    /* NTT(s1), NTT(s2), NTT(t0). */
    for (i = 0; i < l; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N; j++) {
            s1.vec[i].coeffs[j] = dsa_caddq(s1.vec[i].coeffs[j]);
        }
        dsa_poly_ntt(&s1.vec[i]);
    }
    for (i = 0; i < k; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N; j++) {
            s2.vec[i].coeffs[j] = dsa_caddq(s2.vec[i].coeffs[j]);
        }
        dsa_poly_ntt(&s2.vec[i]);
    }
    for (i = 0; i < k; i++) {
        unsigned int j;
        for (j = 0; j < DSA_N; j++) {
            t0.vec[i].coeffs[j] = dsa_caddq(t0.vec[i].coeffs[j]);
        }
        dsa_poly_ntt(&t0.vec[i]);
    }

    /* mu = CRH(tr || pre || msg), with pre = (0x00, ctxlen=0x00) for the
     * empty-context API (FIPS 204 / reference convention). */
    {
        rivide_keccak_state_t hstate;
        static const uint8_t pre[2] = {0x00, 0x00};
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, tr, 64);
        rivide_shake_absorb(&hstate, pre, 2);
        rivide_shake_absorb(&hstate, msg, msglen);
        rivide_shake_squeeze(&hstate, mu, 64);
    }

    /* rho' = CRH(K || rnd || mu) for deterministic signing (rnd = 0^32). */
    {
        rivide_keccak_state_t hstate;
        uint8_t rnd[32];
        unsigned int ri;
        for (ri = 0; ri < 32; ri++) {
            rnd[ri] = 0;
        }
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, K, 32);
        rivide_shake_absorb(&hstate, rnd, 32);
        rivide_shake_absorb(&hstate, mu, 64);
        rivide_shake_squeeze(&hstate, rho_prime, 64);
    }

    /* Rejection sampling loop. */
    int loop_ctr = 0;
    do {
        reject = 0;
        loop_ctr++;
        if (loop_ctr > 10000) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
        /* Sample masking vector y from ExpandMask(rho', nonce). */
        for (i = 0; i < l; i++) {
            dsa_poly_uniform_gamma1(&y.vec[i], rho_prime, 64, (uint16_t)(nonce + (uint16_t)i),
                                    gamma1);
        }
        nonce = (uint16_t)(nonce + (uint16_t)l);

        /* w = A * NTT(y) */
        {
            dsa_polyvecl_t y_hat;
            for (i = 0; i < l; i++) {
                unsigned int j;
                for (j = 0; j < DSA_N; j++) {
                    y_hat.vec[i].coeffs[j] = dsa_caddq(y.vec[i].coeffs[j]);
                }
                dsa_poly_ntt(&y_hat.vec[i]);
            }
            dsa_expand_matrix_mul(&w, rho, &y_hat, k, l);
            for (i = 0; i < k; i++) {
                dsa_poly_invntt(&w.vec[i]);
                dsa_poly_caddq(&w.vec[i]);
            }
        }
        /* Decompose w into w1 (high bits) and w0 (low bits). */
        for (i = 0; i < k; i++) {
            unsigned int j;
            for (j = 0; j < DSA_N; j++) {
                int32_t a0;
                w1.vec[i].coeffs[j] = dsa_decompose(w.vec[i].coeffs[j], &a0, gamma2);
                w0.vec[i].coeffs[j] = a0;
            }
        }
        /* Challenge: c_tilde = H(mu || w1_encode). */
        {
            rivide_keccak_state_t hstate;
            rivide_shake256_init(&hstate);
            rivide_shake_absorb(&hstate, mu, 64);

            /* Encode w1 and absorb. */
            for (i = 0; i < k; i++) {
                uint8_t w1_buf[DSA_N]; /* Sufficient for w1 encoding. */
                unsigned int j;
                size_t w1_bytes;

                if (gamma2 == (DSA_Q - 1) / 88) {
                    /* 6 bits per coefficient, 256 * 6 / 8 = 192 bytes */
                    w1_bytes = 192;
                    for (j = 0; j < DSA_N / 4; j++) {
                        w1_buf[3 * j] =
                            (uint8_t)(w1.vec[i].coeffs[4 * j] | (w1.vec[i].coeffs[4 * j + 1] << 6));
                        w1_buf[3 * j + 1] = (uint8_t)((w1.vec[i].coeffs[4 * j + 1] >> 2) |
                                                      (w1.vec[i].coeffs[4 * j + 2] << 4));
                        w1_buf[3 * j + 2] = (uint8_t)((w1.vec[i].coeffs[4 * j + 2] >> 4) |
                                                      (w1.vec[i].coeffs[4 * j + 3] << 2));
                    }
                } else {
                    /* gamma2 == (Q-1)/32: 4 bits per coeff, 128 bytes */
                    w1_bytes = 128;
                    for (j = 0; j < DSA_N / 2; j++) {
                        w1_buf[j] =
                            (uint8_t)(w1.vec[i].coeffs[2 * j] | (w1.vec[i].coeffs[2 * j + 1] << 4));
                    }
                }
                rivide_shake_absorb(&hstate, w1_buf, w1_bytes);
            }

            uint8_t ctilde[64];
            rivide_shake_squeeze(&hstate, ctilde, ctilde_bytes);

            /* c = SampleInBall(c_tilde). */
            dsa_poly_challenge(&cp, ctilde, ctilde_bytes, tau);

            /* Store c_tilde in signature. */
            for (i = 0; i < (int)ctilde_bytes; i++) {
                sig[i] = ctilde[i];
            }
        }

        /* z = y + c * s1. */
        {
            dsa_poly_t cp_hat;
            unsigned int j;
            for (j = 0; j < DSA_N; j++)
                cp_hat.coeffs[j] = dsa_caddq(cp.coeffs[j]);
            dsa_poly_ntt(&cp_hat);

            for (i = 0; i < l; i++) {
                dsa_poly_pointwise(&z.vec[i], &cp_hat, &s1.vec[i]);
                dsa_poly_invntt(&z.vec[i]);
                dsa_poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
                dsa_poly_reduce(&z.vec[i]);
            }

            /* Check ||z||_inf < gamma1 - beta. */
            {
                int32_t beta = (int32_t)tau * eta;
                for (i = 0; i < l; i++) {
                    if (dsa_poly_chknorm(&z.vec[i], gamma1 - beta)) {
                        reject = 1;
                        break;
                    }
                }
            }

            if (!reject) {
                /* Compute cs2 and ct0. */
                for (i = 0; i < k; i++) {
                    dsa_poly_pointwise(&cs2.vec[i], &cp_hat, &s2.vec[i]);
                    dsa_poly_invntt(&cs2.vec[i]);
                }
                for (i = 0; i < k; i++) {
                    dsa_poly_pointwise(&ct0.vec[i], &cp_hat, &t0.vec[i]);
                    dsa_poly_invntt(&ct0.vec[i]);
                    dsa_poly_reduce(&ct0.vec[i]);
                }

                /* w0 = LowBits(w) - cs2; check ||w0||_inf < gamma2 - beta. */
                {
                    int32_t beta = (int32_t)tau * eta;
                    for (i = 0; i < k; i++) {
                        dsa_poly_sub(&w0.vec[i], &w0.vec[i], &cs2.vec[i]);
                        dsa_poly_reduce(&w0.vec[i]);
                        if (dsa_poly_chknorm(&w0.vec[i], gamma2 - beta)) {
                            reject = 1;
                            break;
                        }
                    }
                }
            }

            if (!reject) {
                /* Check ||ct0||_inf < gamma2. */
                for (i = 0; i < k; i++) {
                    if (dsa_poly_chknorm(&ct0.vec[i], gamma2)) {
                        reject = 1;
                        break;
                    }
                }
            }

            if (!reject) {
                /* h = MakeHint(LowBits(w) - cs2 + ct0, HighBits(w)); retry if too many hints. */
                hint_count = 0;
                for (i = 0; i < k; i++) {
                    dsa_poly_add(&w0.vec[i], &w0.vec[i], &ct0.vec[i]);
                    for (j = 0; j < DSA_N; j++) {
                        h.vec[i].coeffs[j] = (int32_t)dsa_make_hint(w0.vec[i].coeffs[j],
                                                                    w1.vec[i].coeffs[j], gamma2);
                        hint_count += (unsigned int)h.vec[i].coeffs[j];
                    }
                }
                if (hint_count > (unsigned int)omega) {
                    reject = 1;
                }
            }
        }

    } while (reject);

    /* Pack signature: c_tilde || z || h. */
    {
        sig_offset = ctilde_bytes;

        if (gamma1 == (1 << 17)) {
            z_bytes_per_poly = 576;
        } else {
            z_bytes_per_poly = 640;
        }

        for (i = 0; i < l; i++) {
            dsa_poly_pack_z(sig + sig_offset, &z.vec[i], gamma1);
            sig_offset += z_bytes_per_poly;
        }

        sig_offset += dsa_pack_hint(sig + sig_offset, &h, k, omega);
        *siglen = sig_offset;
    }

    /* Cleanse sensitive data. */
    rivide_cleanse(&s1, sizeof(s1));
    rivide_cleanse(&s2, sizeof(s2));
    rivide_cleanse(&t0, sizeof(t0));
    rivide_cleanse(K, sizeof(K));
    rivide_cleanse(rho_prime, sizeof(rho_prime));
    rivide_cleanse(&y, sizeof(y));
    rivide_cleanse(mu, sizeof(mu));

    return RIVIDE_SUCCESS;
}

/**
 * @brief Internal ML-DSA verification.
 */
static rivide_status_t ml_dsa_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                              size_t msglen, const uint8_t *pk, int k, int l,
                                              int32_t gamma1, int32_t gamma2, unsigned int tau,
                                              int omega, size_t ctilde_bytes) {
    uint8_t rho[32], tr[64], mu[64];
    dsa_polyveck_t t1, h, w1_prime;
    dsa_polyvecl_t z;
    dsa_poly_t cp;
    size_t sig_offset;
    size_t z_bytes_per_poly;
    int i;
    int32_t beta;

    if (!sig || !msg || !pk) {
        return RIVIDE_ERR_NULL_PTR;
    }

    (void)siglen;

    /* Unpack public key. */
    dsa_unpack_pk(rho, &t1, pk, k);

    /* tr = H(pk). */
    {
        size_t pk_bytes = 32 + 320 * (size_t)k;
        rivide_shake256(tr, 64, pk, pk_bytes);
    }

    /* mu = CRH(tr || pre || msg), with pre = (0x00, 0x00) for the
     * empty-context API (must match the signing side). */
    {
        rivide_keccak_state_t hstate;
        static const uint8_t pre[2] = {0x00, 0x00};
        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, tr, 64);
        rivide_shake_absorb(&hstate, pre, 2);
        rivide_shake_absorb(&hstate, msg, msglen);
        rivide_shake_squeeze(&hstate, mu, 64);
    }

    /* Unpack signature: c_tilde || z || h. */
    sig_offset = ctilde_bytes;

    if (gamma1 == (1 << 17)) {
        z_bytes_per_poly = 576;
    } else {
        z_bytes_per_poly = 640;
    }

    for (i = 0; i < l; i++) {
        dsa_poly_unpack_z(&z.vec[i], sig + sig_offset, gamma1);
        sig_offset += z_bytes_per_poly;
    }

    /* Check ||z||_inf < gamma1 - beta. */
    beta = (int32_t)tau * RIVIDE_ML_DSA_65_ETA; /* Use appropriate eta. */
    if (k == 8)
        beta = (int32_t)tau * RIVIDE_ML_DSA_87_ETA;
    for (i = 0; i < l; i++) {
        if (dsa_poly_chknorm(&z.vec[i], gamma1 - beta)) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
    }

    /* Unpack hints. */
    if (dsa_unpack_hint(&h, sig + sig_offset, k, omega)) {
        return RIVIDE_ERR_VERIFICATION_FAILED;
    }

    /* c = SampleInBall(c_tilde). */
    dsa_poly_challenge(&cp, sig, ctilde_bytes, tau);

    /* Compute w1' = UseHint(h, A*NTT(z) - c*NTT(t1*2^d)). */
    {
        dsa_polyvecl_t z_hat;
        dsa_poly_t cp_hat;
        unsigned int j;

        /* NTT(z). */
        for (i = 0; i < l; i++) {
            for (j = 0; j < DSA_N; j++)
                z_hat.vec[i].coeffs[j] = dsa_caddq(z.vec[i].coeffs[j]);
            dsa_poly_ntt(&z_hat.vec[i]);
        }

        /* NTT(c). */
        for (j = 0; j < DSA_N; j++)
            cp_hat.coeffs[j] = dsa_caddq(cp.coeffs[j]);
        dsa_poly_ntt(&cp_hat);

        /* A * z_hat. */
        dsa_expand_matrix_mul(&w1_prime, rho, &z_hat, k, l);
        for (i = 0; i < k; i++) {
            dsa_poly_invntt(&w1_prime.vec[i]);
        }

        /* Subtract c * t1 * 2^d. */
        for (i = 0; i < k; i++) {
            dsa_poly_t ct1;
            /* t1 * 2^d in NTT domain. */
            dsa_poly_t t1_shifted;
            for (j = 0; j < DSA_N; j++) {
                t1_shifted.coeffs[j] = dsa_caddq(dsa_reduce32(t1.vec[i].coeffs[j] << DSA_D_BITS));
            }
            dsa_poly_ntt(&t1_shifted);
            dsa_poly_pointwise(&ct1, &cp_hat, &t1_shifted);
            dsa_poly_invntt(&ct1);

            dsa_poly_sub(&w1_prime.vec[i], &w1_prime.vec[i], &ct1);
            dsa_poly_caddq(&w1_prime.vec[i]);

            /* UseHint. */
            for (j = 0; j < DSA_N; j++) {
                w1_prime.vec[i].coeffs[j] = dsa_use_hint(w1_prime.vec[i].coeffs[j],
                                                         (unsigned int)h.vec[i].coeffs[j], gamma2);
            }
        }
    }

    /* Recompute c_tilde' = H(mu || w1_encode) and compare. */
    {
        rivide_keccak_state_t hstate;
        uint8_t ctilde_prime[64];

        rivide_shake256_init(&hstate);
        rivide_shake_absorb(&hstate, mu, 64);

        for (i = 0; i < k; i++) {
            uint8_t w1_buf[DSA_N];
            unsigned int j;
            size_t w1_bytes;

            if (gamma2 == (DSA_Q - 1) / 88) {
                w1_bytes = 192;
                for (j = 0; j < DSA_N / 4; j++) {
                    w1_buf[3 * j] = (uint8_t)(w1_prime.vec[i].coeffs[4 * j] |
                                              (w1_prime.vec[i].coeffs[4 * j + 1] << 6));
                    w1_buf[3 * j + 1] = (uint8_t)((w1_prime.vec[i].coeffs[4 * j + 1] >> 2) |
                                                  (w1_prime.vec[i].coeffs[4 * j + 2] << 4));
                    w1_buf[3 * j + 2] = (uint8_t)((w1_prime.vec[i].coeffs[4 * j + 2] >> 4) |
                                                  (w1_prime.vec[i].coeffs[4 * j + 3] << 2));
                }
            } else {
                w1_bytes = 128;
                for (j = 0; j < DSA_N / 2; j++) {
                    w1_buf[j] = (uint8_t)(w1_prime.vec[i].coeffs[2 * j] |
                                          (w1_prime.vec[i].coeffs[2 * j + 1] << 4));
                }
            }
            rivide_shake_absorb(&hstate, w1_buf, w1_bytes);
        }

        rivide_shake_squeeze(&hstate, ctilde_prime, ctilde_bytes);

        if (rivide_ct_memcmp(sig, ctilde_prime, ctilde_bytes) != 0) {
            return RIVIDE_ERR_VERIFICATION_FAILED;
        }
    }

    return RIVIDE_SUCCESS;
}

rivide_status_t rivide_ml_dsa_65_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk)
        return RIVIDE_ERR_NULL_PTR;
    return ml_dsa_keygen_internal(pk, sk, RIVIDE_ML_DSA_65_K, RIVIDE_ML_DSA_65_L,
                                  RIVIDE_ML_DSA_65_ETA, RIVIDE_ML_DSA_65_GAMMA2);
}

rivide_status_t rivide_ml_dsa_65_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk) {
    return ml_dsa_sign_internal(sig, siglen, msg, msglen, sk, RIVIDE_ML_DSA_65_K,
                                RIVIDE_ML_DSA_65_L, RIVIDE_ML_DSA_65_ETA, RIVIDE_ML_DSA_65_GAMMA1,
                                RIVIDE_ML_DSA_65_GAMMA2, RIVIDE_ML_DSA_TAU_65,
                                RIVIDE_ML_DSA_65_OMEGA, RIVIDE_ML_DSA_65_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_65_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk) {
    (void)siglen;
    return ml_dsa_verify_internal(sig, siglen, msg, msglen, pk, RIVIDE_ML_DSA_65_K,
                                  RIVIDE_ML_DSA_65_L, RIVIDE_ML_DSA_65_GAMMA1,
                                  RIVIDE_ML_DSA_65_GAMMA2, RIVIDE_ML_DSA_TAU_65,
                                  RIVIDE_ML_DSA_65_OMEGA, RIVIDE_ML_DSA_65_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_87_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk)
        return RIVIDE_ERR_NULL_PTR;
    return ml_dsa_keygen_internal(pk, sk, RIVIDE_ML_DSA_87_K, RIVIDE_ML_DSA_87_L,
                                  RIVIDE_ML_DSA_87_ETA, RIVIDE_ML_DSA_87_GAMMA2);
}

rivide_status_t rivide_ml_dsa_87_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                                      size_t msglen, const uint8_t *sk) {
    return ml_dsa_sign_internal(sig, siglen, msg, msglen, sk, RIVIDE_ML_DSA_87_K,
                                RIVIDE_ML_DSA_87_L, RIVIDE_ML_DSA_87_ETA, RIVIDE_ML_DSA_87_GAMMA1,
                                RIVIDE_ML_DSA_87_GAMMA2, RIVIDE_ML_DSA_TAU_87,
                                RIVIDE_ML_DSA_87_OMEGA, RIVIDE_ML_DSA_87_CTILDEBYTES);
}

rivide_status_t rivide_ml_dsa_87_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                                        size_t msglen, const uint8_t *pk) {
    (void)siglen;
    return ml_dsa_verify_internal(sig, siglen, msg, msglen, pk, RIVIDE_ML_DSA_87_K,
                                  RIVIDE_ML_DSA_87_L, RIVIDE_ML_DSA_87_GAMMA1,
                                  RIVIDE_ML_DSA_87_GAMMA2, RIVIDE_ML_DSA_TAU_87,
                                  RIVIDE_ML_DSA_87_OMEGA, RIVIDE_ML_DSA_87_CTILDEBYTES);
}
