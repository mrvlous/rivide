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
 * @file napi_kem.c
 * @brief Node-API bindings for NIST FIPS 203 ML-KEM-768 and ML-KEM-1024.
 */

#include "napi_common.h"

static napi_value js_ml_kem_768_keygen(napi_env env, napi_callback_info info) {
    (void)info;
    uint8_t pk[RIVIDE_ML_KEM_768_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_768_SK_BYTES];

    rivide_status_t status = rivide_ml_kem_768_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-768 keypair generation failed");
    }

    napi_value obj, pk_buf, sk_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_768_PK_BYTES, pk, NULL, &pk_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_768_SK_BYTES, sk, NULL, &sk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "publicKey", pk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "secretKey", sk_buf));

    rivide_cleanse(sk, sizeof(sk));
    return obj;
}

static napi_value js_ml_kem_768_encaps(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: publicKey (Buffer)");
    }

    uint8_t *pk_data = NULL;
    size_t pk_len = 0;
    if (!get_buffer_arg(env, args[0], &pk_data, &pk_len) || pk_len != RIVIDE_ML_KEM_768_PK_BYTES) {
        THROW_TYPE_ERROR(env, "publicKey must be a Buffer of exactly 1184 bytes");
    }

    uint8_t ct[RIVIDE_ML_KEM_768_CT_BYTES];
    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];

    rivide_status_t status = rivide_ml_kem_768_encaps(ct, ss, pk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-768 encapsulation failed");
    }

    napi_value obj, ct_buf, ss_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_768_CT_BYTES, ct, NULL, &ct_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_SS_BYTES, ss, NULL, &ss_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "ciphertext", ct_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "sharedSecret", ss_buf));

    rivide_cleanse(ss, sizeof(ss));
    return obj;
}

static napi_value js_ml_kem_768_decaps(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: ciphertext (Buffer), secretKey (Buffer)");
    }

    uint8_t *ct_data = NULL;
    size_t ct_len = 0;
    if (!get_buffer_arg(env, args[0], &ct_data, &ct_len) || ct_len != RIVIDE_ML_KEM_768_CT_BYTES) {
        THROW_TYPE_ERROR(env, "ciphertext must be a Buffer of exactly 1088 bytes");
    }

    uint8_t *sk_data = NULL;
    size_t sk_len = 0;
    if (!get_buffer_arg(env, args[1], &sk_data, &sk_len) || sk_len != RIVIDE_ML_KEM_768_SK_BYTES) {
        THROW_TYPE_ERROR(env, "secretKey must be a Buffer of exactly 2400 bytes");
    }

    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t status = rivide_ml_kem_768_decaps(ss, ct_data, sk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-768 decapsulation failed");
    }

    napi_value ss_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_SS_BYTES, ss, NULL, &ss_buf));
    rivide_cleanse(ss, sizeof(ss));
    return ss_buf;
}

static napi_value js_ml_kem_1024_keygen(napi_env env, napi_callback_info info) {
    (void)info;
    uint8_t pk[RIVIDE_ML_KEM_1024_PK_BYTES];
    uint8_t sk[RIVIDE_ML_KEM_1024_SK_BYTES];

    rivide_status_t status = rivide_ml_kem_1024_keygen(pk, sk);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-1024 keypair generation failed");
    }

    napi_value obj, pk_buf, sk_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_1024_PK_BYTES, pk, NULL, &pk_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_1024_SK_BYTES, sk, NULL, &sk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "publicKey", pk_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "secretKey", sk_buf));

    rivide_cleanse(sk, sizeof(sk));
    return obj;
}

static napi_value js_ml_kem_1024_encaps(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: publicKey (Buffer)");
    }

    uint8_t *pk_data = NULL;
    size_t pk_len = 0;
    if (!get_buffer_arg(env, args[0], &pk_data, &pk_len) || pk_len != RIVIDE_ML_KEM_1024_PK_BYTES) {
        THROW_TYPE_ERROR(env, "publicKey must be a Buffer of exactly 1568 bytes");
    }

    uint8_t ct[RIVIDE_ML_KEM_1024_CT_BYTES];
    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];

    rivide_status_t status = rivide_ml_kem_1024_encaps(ct, ss, pk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-1024 encapsulation failed");
    }

    napi_value obj, ct_buf, ss_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_1024_CT_BYTES, ct, NULL, &ct_buf));
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_SS_BYTES, ss, NULL, &ss_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "ciphertext", ct_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "sharedSecret", ss_buf));

    rivide_cleanse(ss, sizeof(ss));
    return obj;
}

static napi_value js_ml_kem_1024_decaps(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: ciphertext (Buffer), secretKey (Buffer)");
    }

    uint8_t *ct_data = NULL;
    size_t ct_len = 0;
    if (!get_buffer_arg(env, args[0], &ct_data, &ct_len) || ct_len != RIVIDE_ML_KEM_1024_CT_BYTES) {
        THROW_TYPE_ERROR(env, "ciphertext must be a Buffer of exactly 1568 bytes");
    }

    uint8_t *sk_data = NULL;
    size_t sk_len = 0;
    if (!get_buffer_arg(env, args[1], &sk_data, &sk_len) || sk_len != RIVIDE_ML_KEM_1024_SK_BYTES) {
        THROW_TYPE_ERROR(env, "secretKey must be a Buffer of exactly 3168 bytes");
    }

    uint8_t ss[RIVIDE_ML_KEM_SS_BYTES];
    rivide_status_t status = rivide_ml_kem_1024_decaps(ss, ct_data, sk_data);
    if (status != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "ML-KEM-1024 decapsulation failed");
    }

    napi_value ss_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, RIVIDE_ML_KEM_SS_BYTES, ss, NULL, &ss_buf));
    rivide_cleanse(ss, sizeof(ss));
    return ss_buf;
}

void init_napi_kem(napi_env env, napi_value exports) {
    export_function(env, exports, "mlKem768Keygen", js_ml_kem_768_keygen);
    export_function(env, exports, "mlKem768Encaps", js_ml_kem_768_encaps);
    export_function(env, exports, "mlKem768Decaps", js_ml_kem_768_decaps);
    export_function(env, exports, "mlKem1024Keygen", js_ml_kem_1024_keygen);
    export_function(env, exports, "mlKem1024Encaps", js_ml_kem_1024_encaps);
    export_function(env, exports, "mlKem1024Decaps", js_ml_kem_1024_decaps);
}
