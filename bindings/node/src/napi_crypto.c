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
 * @file napi_crypto.c
 * @brief Node-API bindings for SHA-3, SHAKE XOF, and AES-128/256-GCM AEAD.
 */

#include "napi_common.h"

static napi_value js_sha3_256(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: data (Buffer)");
    }

    uint8_t *in_data = NULL;
    size_t in_len = 0;
    if (!get_buffer_arg(env, args[0], &in_data, &in_len)) {
        THROW_TYPE_ERROR(env, "data must be a Buffer");
    }

    uint8_t out[RIVIDE_SHA3_256_BYTES];
    rivide_sha3_256(out, in_data, in_len);

    napi_value out_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, sizeof(out), out, NULL, &out_buf));
    return out_buf;
}

static napi_value js_sha3_512(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 1) {
        THROW_TYPE_ERROR(env, "Expected 1 argument: data (Buffer)");
    }

    uint8_t *in_data = NULL;
    size_t in_len = 0;
    if (!get_buffer_arg(env, args[0], &in_data, &in_len)) {
        THROW_TYPE_ERROR(env, "data must be a Buffer");
    }

    uint8_t out[RIVIDE_SHA3_512_BYTES];
    rivide_sha3_512(out, in_data, in_len);

    napi_value out_buf;
    NAPI_CHECK(env, napi_create_buffer_copy(env, sizeof(out), out, NULL, &out_buf));
    return out_buf;
}

static napi_value js_shake128(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: data (Buffer), outputLength (number)");
    }

    uint8_t *in_data = NULL;
    size_t in_len = 0;
    if (!get_buffer_arg(env, args[0], &in_data, &in_len)) {
        THROW_TYPE_ERROR(env, "data must be a Buffer");
    }

    int64_t out_len_val = 0;
    NAPI_CHECK(env, napi_get_value_int64(env, args[1], &out_len_val));
    if (out_len_val <= 0 || out_len_val > 1048576) {
        THROW_TYPE_ERROR(env, "outputLength must be a positive number up to 1MB");
    }
    size_t out_len = (size_t)out_len_val;

    napi_value out_buf;
    uint8_t *out_data = NULL;
    if (napi_create_buffer(env, out_len, (void **)&out_data, &out_buf) != napi_ok) {
        THROW_ERROR(env, "Failed to allocate return Buffer");
    }

    rivide_shake128(out_data, out_len, in_data, in_len);
    return out_buf;
}

static napi_value js_shake256(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 2) {
        THROW_TYPE_ERROR(env, "Expected 2 arguments: data (Buffer), outputLength (number)");
    }

    uint8_t *in_data = NULL;
    size_t in_len = 0;
    if (!get_buffer_arg(env, args[0], &in_data, &in_len)) {
        THROW_TYPE_ERROR(env, "data must be a Buffer");
    }

    int64_t out_len_val = 0;
    NAPI_CHECK(env, napi_get_value_int64(env, args[1], &out_len_val));
    if (out_len_val <= 0 || out_len_val > 1048576) {
        THROW_TYPE_ERROR(env, "outputLength must be a positive number up to 1MB");
    }
    size_t out_len = (size_t)out_len_val;

    napi_value out_buf;
    uint8_t *out_data = NULL;
    if (napi_create_buffer(env, out_len, (void **)&out_data, &out_buf) != napi_ok) {
        THROW_ERROR(env, "Failed to allocate return Buffer");
    }

    rivide_shake256(out_data, out_len, in_data, in_len);
    return out_buf;
}

static napi_value js_aes_gcm_encrypt_internal(napi_env env, napi_callback_info info, bool is_256) {
    size_t argc = 4;
    napi_value args[4];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 3) {
        THROW_TYPE_ERROR(env, "Expected at least 3 arguments: key (Buffer), iv (Buffer), plaintext "
                              "(Buffer), [aad (Buffer)]");
    }

    uint8_t *key_data = NULL;
    size_t key_len = 0;
    size_t expected_key = is_256 ? 32 : 16;
    if (!get_buffer_arg(env, args[0], &key_data, &key_len) || key_len != expected_key) {
        THROW_TYPE_ERROR(env, is_256 ? "key must be 32 bytes for AES-256-GCM"
                                     : "key must be 16 bytes for AES-128-GCM");
    }

    uint8_t *iv_data = NULL;
    size_t iv_len = 0;
    if (!get_buffer_arg(env, args[1], &iv_data, &iv_len) || iv_len != RIVIDE_GCM_IV_BYTES) {
        THROW_TYPE_ERROR(env, "iv must be exactly 12 bytes");
    }

    uint8_t *pt_data = NULL;
    size_t pt_len = 0;
    if (!get_buffer_arg(env, args[2], &pt_data, &pt_len)) {
        THROW_TYPE_ERROR(env, "plaintext must be a Buffer");
    }

    uint8_t *aad_data = NULL;
    size_t aad_len = 0;
    if (argc >= 4 && args[3] != NULL) {
        napi_valuetype t;
        NAPI_CHECK(env, napi_typeof(env, args[3], &t));
        if (t != napi_null && t != napi_undefined) {
            if (!get_buffer_arg(env, args[3], &aad_data, &aad_len)) {
                THROW_TYPE_ERROR(env, "aad must be a Buffer if provided");
            }
        }
    }

    rivide_aes_key_t key_schedule;
    if (is_256) {
        if (rivide_aes256_key_expand(&key_schedule, key_data) != RIVIDE_SUCCESS) {
            THROW_ERROR(env, "AES-256 key expansion failed");
        }
    } else {
        if (rivide_aes128_key_expand(&key_schedule, key_data) != RIVIDE_SUCCESS) {
            THROW_ERROR(env, "AES-128 key expansion failed");
        }
    }

    napi_value obj, ct_buf, tag_buf;
    NAPI_CHECK(env, napi_create_object(env, &obj));

    uint8_t *ct_data = NULL;
    if (napi_create_buffer(env, pt_len, (void **)&ct_data, &ct_buf) != napi_ok) {
        rivide_cleanse(&key_schedule, sizeof(key_schedule));
        THROW_ERROR(env, "Failed to allocate ciphertext Buffer");
    }

    uint8_t *tag_data = NULL;
    if (napi_create_buffer(env, RIVIDE_GCM_TAG_BYTES, (void **)&tag_data, &tag_buf) != napi_ok) {
        rivide_cleanse(&key_schedule, sizeof(key_schedule));
        THROW_ERROR(env, "Failed to allocate tag Buffer");
    }

    rivide_status_t status = rivide_aes_gcm_encrypt(&key_schedule, iv_data, aad_data, aad_len,
                                                    pt_data, pt_len, ct_data, tag_data);
    rivide_cleanse(&key_schedule, sizeof(key_schedule));

    if (status != RIVIDE_SUCCESS) {
        if (ct_data && pt_len > 0) {
            rivide_cleanse(ct_data, pt_len);
        }
        if (tag_data) {
            rivide_cleanse(tag_data, RIVIDE_GCM_TAG_BYTES);
        }
        THROW_ERROR(env, "AES-GCM encryption failed");
    }

    NAPI_CHECK(env, napi_set_named_property(env, obj, "ciphertext", ct_buf));
    NAPI_CHECK(env, napi_set_named_property(env, obj, "tag", tag_buf));
    return obj;
}

static napi_value js_aes_gcm_decrypt_internal(napi_env env, napi_callback_info info, bool is_256) {
    size_t argc = 5;
    napi_value args[5];
    NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc < 4) {
        THROW_TYPE_ERROR(env, "Expected at least 4 arguments: key (Buffer), iv (Buffer), "
                              "ciphertext (Buffer), tag (Buffer), [aad (Buffer)]");
    }

    uint8_t *key_data = NULL;
    size_t key_len = 0;
    size_t expected_key = is_256 ? 32 : 16;
    if (!get_buffer_arg(env, args[0], &key_data, &key_len) || key_len != expected_key) {
        THROW_TYPE_ERROR(env, is_256 ? "key must be 32 bytes for AES-256-GCM"
                                     : "key must be 16 bytes for AES-128-GCM");
    }

    uint8_t *iv_data = NULL;
    size_t iv_len = 0;
    if (!get_buffer_arg(env, args[1], &iv_data, &iv_len) || iv_len != RIVIDE_GCM_IV_BYTES) {
        THROW_TYPE_ERROR(env, "iv must be exactly 12 bytes");
    }

    uint8_t *ct_data = NULL;
    size_t ct_len = 0;
    if (!get_buffer_arg(env, args[2], &ct_data, &ct_len)) {
        THROW_TYPE_ERROR(env, "ciphertext must be a Buffer");
    }

    uint8_t *tag_data = NULL;
    size_t tag_len = 0;
    if (!get_buffer_arg(env, args[3], &tag_data, &tag_len) || tag_len != RIVIDE_GCM_TAG_BYTES) {
        THROW_TYPE_ERROR(env, "tag must be exactly 16 bytes");
    }

    uint8_t *aad_data = NULL;
    size_t aad_len = 0;
    if (argc >= 5 && args[4] != NULL) {
        napi_valuetype t;
        NAPI_CHECK(env, napi_typeof(env, args[4], &t));
        if (t != napi_null && t != napi_undefined) {
            if (!get_buffer_arg(env, args[4], &aad_data, &aad_len)) {
                THROW_TYPE_ERROR(env, "aad must be a Buffer if provided");
            }
        }
    }

    rivide_aes_key_t key_schedule;
    if (is_256) {
        if (rivide_aes256_key_expand(&key_schedule, key_data) != RIVIDE_SUCCESS) {
            THROW_ERROR(env, "AES-256 key expansion failed");
        }
    } else {
        if (rivide_aes128_key_expand(&key_schedule, key_data) != RIVIDE_SUCCESS) {
            THROW_ERROR(env, "AES-128 key expansion failed");
        }
    }

    napi_value pt_buf;
    uint8_t *pt_data = NULL;
    if (napi_create_buffer(env, ct_len, (void **)&pt_data, &pt_buf) != napi_ok) {
        rivide_cleanse(&key_schedule, sizeof(key_schedule));
        THROW_ERROR(env, "Failed to allocate plaintext Buffer");
    }

    rivide_status_t status = rivide_aes_gcm_decrypt(&key_schedule, iv_data, aad_data, aad_len,
                                                    ct_data, ct_len, tag_data, pt_data);
    rivide_cleanse(&key_schedule, sizeof(key_schedule));

    if (status != RIVIDE_SUCCESS) {
        if (pt_data && ct_len > 0) {
            rivide_cleanse(pt_data, ct_len);
        }
        THROW_ERROR(env, "AES-GCM authentication verification failed (invalid ciphertext or tag)");
    }

    return pt_buf;
}

static napi_value js_aes128_gcm_encrypt(napi_env env, napi_callback_info info) {
    return js_aes_gcm_encrypt_internal(env, info, false);
}

static napi_value js_aes128_gcm_decrypt(napi_env env, napi_callback_info info) {
    return js_aes_gcm_decrypt_internal(env, info, false);
}

static napi_value js_aes256_gcm_encrypt(napi_env env, napi_callback_info info) {
    return js_aes_gcm_encrypt_internal(env, info, true);
}

static napi_value js_aes256_gcm_decrypt(napi_env env, napi_callback_info info) {
    return js_aes_gcm_decrypt_internal(env, info, true);
}

void init_napi_crypto(napi_env env, napi_value exports) {
    export_function(env, exports, "sha3_256", js_sha3_256);
    export_function(env, exports, "sha3_512", js_sha3_512);
    export_function(env, exports, "shake128", js_shake128);
    export_function(env, exports, "shake256", js_shake256);
    export_function(env, exports, "aes128GcmEncrypt", js_aes128_gcm_encrypt);
    export_function(env, exports, "aes128GcmDecrypt", js_aes128_gcm_decrypt);
    export_function(env, exports, "aes256GcmEncrypt", js_aes256_gcm_encrypt);
    export_function(env, exports, "aes256GcmDecrypt", js_aes256_gcm_decrypt);
}
