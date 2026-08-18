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
 * @file napi_utils.c
 * @brief Node-API bindings for memory cleansing, OS entropy, constant-time comparison, and SIMD
 * queries.
 */

#include "napi_common.h"

static napi_value js_cleanse(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: buffer (Buffer)");
    }

    uint8_t *data = NULL;
    size_t len = 0;
    if (get_buffer_arg(env, args[0], &data, &len)) {
        if (len > 0 && data != NULL) {
            rivide_cleanse(data, len);
        }
    }

    napi_value undefined_val;
    NAPI_CHECK(env, napi_get_undefined(env, &undefined_val));
    return undefined_val;
}

static napi_value js_randombytes(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: length (number)");
    }

    int64_t len_val = 0;
    NAPI_CHECK(env, napi_get_value_int64(env, args[0], &len_val));
    if (len_val < 0 || len_val > 1048576) {
        THROW_TYPE_ERROR(env, "length must be between 0 and 1MB");
    }

    size_t len = (size_t)len_val;
    napi_value out_buf;
    uint8_t *buf = NULL;
    if (napi_create_buffer(env, len, (void **)&buf, &out_buf) != napi_ok) {
        THROW_ERROR(env, "Failed to create return Buffer");
    }

    if (len > 0) {
        if (rivide_randombytes(buf, len) != RIVIDE_SUCCESS) {
            THROW_ERROR(env, "OS entropy generation failed");
        }
    }
    return out_buf;
}

static napi_value js_ct_memcmp(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: a (Buffer), b (Buffer)");
    }

    uint8_t *a_data = NULL;
    size_t a_len = 0;
    if (!get_buffer_arg(env, args[0], &a_data, &a_len)) {
        THROW_TYPE_ERROR(env, "Argument 1 must be a Buffer");
    }

    uint8_t *b_data = NULL;
    size_t b_len = 0;
    if (!get_buffer_arg(env, args[1], &b_data, &b_len)) {
        THROW_TYPE_ERROR(env, "Argument 2 must be a Buffer");
    }

    if (a_len != b_len) {
        napi_value diff_res;
        NAPI_CHECK(env, napi_create_int32(env, 1, &diff_res));
        return diff_res;
    }

    int res = rivide_ct_memcmp(a_data, b_data, a_len);
    napi_value res_val;
    NAPI_CHECK(env, napi_create_int32(env, res, &res_val));
    return res_val;
}

static napi_value js_get_simd_caps(napi_env env, napi_callback_info info) {
    (void)info;
    uint32_t feats = rivide_get_cpu_features();

    napi_value obj, aesni_val, armce_val, avx2_val, neon_val, mask_val;
    NAPI_CHECK(env, napi_create_object(env, &obj));
    NAPI_CHECK(env, napi_get_boolean(env, (feats & 0x01) != 0, &aesni_val));
    NAPI_CHECK(env, napi_get_boolean(env, (feats & 0x02) != 0, &armce_val));
    NAPI_CHECK(env, napi_get_boolean(env, (feats & 0x04) != 0, &avx2_val));
    NAPI_CHECK(env, napi_get_boolean(env, (feats & 0x08) != 0, &neon_val));
    NAPI_CHECK(env, napi_create_uint32(env, feats, &mask_val));

    NAPI_CHECK(env, napi_set_named_property(env, obj, "hasAesni", aesni_val));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "hasArmCrypto", armce_val));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "hasAvx2", avx2_val));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "hasNeon", neon_val));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "bitmask", mask_val));

    return obj;
}

static napi_value js_version(napi_env env, napi_callback_info info) {
    (void)info;
    const char *ver_str = rivide_version_string();
    napi_value ver_val;
    NAPI_CHECK(env, napi_create_string_utf8(env, ver_str, NAPI_AUTO_LENGTH, &ver_val));
    return ver_val;
}

void init_napi_utils(napi_env env, napi_value exports) {
    export_function(env, exports, "cleanse", js_cleanse);
    export_function(env, exports, "randombytes", js_randombytes);
    export_function(env, exports, "ctMemcmp", js_ct_memcmp);
    export_function(env, exports, "getSimdCaps", js_get_simd_caps);
    export_function(env, exports, "version", js_version);
}
