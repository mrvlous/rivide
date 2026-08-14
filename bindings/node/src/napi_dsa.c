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
 * @file napi_dsa.c
 * @brief Node-API bindings for NIST FIPS 204 ML-DSA-65 and ML-DSA-87 digital signatures.
 */

#include "napi_common.h"

static napi_value js_ml_dsa_65_keygen(napi_env env, napi_callback_info info) {
    (void)info;
    uint8_t pk[RIVIDE_ML_DSA_65_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_65_SK_BYTES];

    rivide_status_t status = rivide_ml_dsa_65_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-DSA-65 keypair generation failed");
    }

    napi_value obj, pk_buf, sk_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_DSA_65_PK_BYTES, pk, NULL, &pk_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_DSA_65_SK_BYTES, sk, NULL, &sk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "publicKey", pk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "secretKey", sk_buf));

    rivide_cleanse(sk, sizeof(sk));
    return obj;
}

static napi_value js_ml_dsa_65_sign(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: message (Buffer), secretKey (Buffer)");
    }

    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    if (!get_buffer_arg(env, args[0], &msg_data, &msg_len)) {
        THROW_TYPE_ERROR(env, "message must be a Buffer");
    }

    uint8_t *sk_data = NULL;
    size_t sk_len = 0;
    if (!get_buffer_arg(env, args[1], &sk_data, &sk_len) || sk_len != RIVIDE_ML_DSA_65_SK_BYTES) {
        THROW_TYPE_ERROR(env, "secretKey must be a Buffer of exactly 4032 bytes");
    }

    uint8_t sig[RIVIDE_ML_DSA_65_SIG_BYTES];
    size_t siglen = sizeof(sig);

    rivide_status_t status = rivide_ml_dsa_65_sign(sig, &siglen, msg_data, msg_len, sk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-DSA-65 signing failed");
    }

    napi_value sig_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, siglen, sig, NULL, &sig_buf));
    return sig_buf;
}

static napi_value js_ml_dsa_65_verify(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 3) {
        THROW_TYPE_ERROR(
            env, "Expected 3 arguments: signature (Buffer), message (Buffer), publicKey (Buffer)");
    }

    uint8_t *sig_data = NULL;
    size_t sig_len = 0;
    if (!get_buffer_arg(env, args[0], &sig_data, &sig_len)) {
        THROW_TYPE_ERROR(env, "signature must be a Buffer");
    }

    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    if (!get_buffer_arg(env, args[1], &msg_data, &msg_len)) {
        THROW_TYPE_ERROR(env, "message must be a Buffer");
    }

    uint8_t *pk_data = NULL;
    size_t pk_len = 0;
    if (!get_buffer_arg(env, args[2], &pk_data, &pk_len) || pk_len != RIVIDE_ML_DSA_65_PK_BYTES) {
        THROW_TYPE_ERROR(env, "publicKey must be a Buffer of exactly 1952 bytes");
    }

    rivide_status_t status = rivide_ml_dsa_65_verify(sig_data, sig_len, msg_data, msg_len, pk_data);
    napi_value result;
    NAPI_CHECK(env, napi_get_boolean(env, (status == RIVIDE_SUCCESS), &result));
    return result;
}

static napi_value js_ml_dsa_87_keygen(napi_env env, napi_callback_info info) {
    (void)info;
    uint8_t pk[RIVIDE_ML_DSA_87_PK_BYTES];
    uint8_t sk[RIVIDE_ML_DSA_87_SK_BYTES];

    rivide_status_t status = rivide_ml_dsa_87_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-DSA-87 keypair generation failed");
    }

    napi_value obj, pk_buf, sk_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_DSA_87_PK_BYTES, pk, NULL, &pk_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_DSA_87_SK_BYTES, sk, NULL, &sk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "publicKey", pk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "secretKey", sk_buf));

    rivide_cleanse(sk, sizeof(sk));
    return obj;
}

static napi_value js_ml_dsa_87_sign(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: message (Buffer), secretKey (Buffer)");
    }

    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    if (!get_buffer_arg(env, args[0], &msg_data, &msg_len)) {
        THROW_TYPE_ERROR(env, "message must be a Buffer");
    }

    uint8_t *sk_data = NULL;
    size_t sk_len = 0;
    if (!get_buffer_arg(env, args[1], &sk_data, &sk_len) || sk_len != RIVIDE_ML_DSA_87_SK_BYTES) {
        THROW_TYPE_ERROR(env, "secretKey must be a Buffer of exactly 4896 bytes");
    }

    uint8_t sig[RIVIDE_ML_DSA_87_SIG_BYTES];
    size_t siglen = sizeof(sig);

    rivide_status_t status = rivide_ml_dsa_87_sign(sig, &siglen, msg_data, msg_len, sk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-DSA-87 signing failed");
    }

    napi_value sig_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, siglen, sig, NULL, &sig_buf));
    return sig_buf;
}

static napi_value js_ml_dsa_87_verify(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 3) {
        THROW_TYPE_ERROR(
            env, "Expected 3 arguments: signature (Buffer), message (Buffer), publicKey (Buffer)");
    }

    uint8_t *sig_data = NULL;
    size_t sig_len = 0;
    if (!get_buffer_arg(env, args[0], &sig_data, &sig_len)) {
        THROW_TYPE_ERROR(env, "signature must be a Buffer");
    }

    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    if (!get_buffer_arg(env, args[1], &msg_data, &msg_len)) {
        THROW_TYPE_ERROR(env, "message must be a Buffer");
    }

    uint8_t *pk_data = NULL;
    size_t pk_len = 0;
    if (!get_buffer_arg(env, args[2], &pk_data, &pk_len) || pk_len != RIVIDE_ML_DSA_87_PK_BYTES) {
        THROW_TYPE_ERROR(env, "publicKey must be a Buffer of exactly 2592 bytes");
    }

    rivide_status_t status = rivide_ml_dsa_87_verify(sig_data, sig_len, msg_data, msg_len, pk_data);
    napi_value result;
    NAPI_CHECK(env, napi_get_boolean(env, (status == RIVIDE_SUCCESS), &result));
    return result;
}

void init_napi_dsa(napi_env env, napi_value exports) {
    export_function(env, exports, "mlDsa65Keygen", js_ml_dsa_65_keygen);
    export_function(env, exports, "mlDsa65Sign", js_ml_dsa_65_sign);
    export_function(env, exports, "mlDsa65Verify", js_ml_dsa_65_verify);
    export_function(env, exports, "mlDsa87Keygen", js_ml_dsa_87_keygen);
    export_function(env, exports, "mlDsa87Sign", js_ml_dsa_87_sign);
    export_function(env, exports, "mlDsa87Verify", js_ml_dsa_87_verify);
}
