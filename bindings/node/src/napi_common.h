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
 * @file napi_common.h
 * @brief Common helper macros and type conversions for Rivide Node-API native bindings.
 */

#ifndef RIVIDE_NAPI_COMMON_H
#define RIVIDE_NAPI_COMMON_H

#define NAPI_VERSION 8
#include <node_api.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rivide/crypto/aes_gcm.h"
#include "rivide/crypto/sha3.h"
#include "rivide/pqc/ml_dsa.h"
#include "rivide/pqc/ml_kem.h"
#include "rivide/pqc/ntt_simd.h"
#include "rivide/rivide.h"
#include "rivide/utils/mem.h"
#include "rivide/utils/random.h"

#define NAPI_CHECK(env, call)                                               \
    do {                                                                    \
        napi_status _status = (call);                                       \
        if (_status != napi_ok) {                                           \
            napi_throw_error((env), NULL, "Node-API internal call failed"); \
            return NULL;                                                    \
        }                                                                   \
    } while (0)

#define THROW_TYPE_ERROR(env, msg)                 \
    do {                                           \
        napi_throw_type_error((env), NULL, (msg)); \
        return NULL;                               \
    } while (0)

#define THROW_ERROR(env, msg)                 \
    do {                                      \
        napi_throw_error((env), NULL, (msg)); \
        return NULL;                          \
    } while (0)

/* Helper to get buffer data and length from a JavaScript argument. */
static inline bool get_buffer_arg(napi_env env, napi_value value, uint8_t **data, size_t *length) {
    bool is_buffer = false;
    if (napi_is_buffer(env, value, &is_buffer) != napi_ok || !is_buffer) {
        return false;
    }
    void *buf_ptr = NULL;
    if (napi_get_buffer_info(env, value, &buf_ptr, length) != napi_ok) {
        return false;
    }
    if (*length == 0) {
        *data = (uint8_t *)"";
        return true;
    }
    if (!buf_ptr) {
        return false;
    }
    *data = (uint8_t *)buf_ptr;
    return true;
}

/* Helper to export a native C function onto the target JS object. */
static inline void export_function(napi_env env, napi_value exports, const char *name,
                                   napi_callback cb) {
    napi_value fn;
    napi_create_function(env, name, NAPI_AUTO_LENGTH, cb, NULL, &fn);
    napi_set_named_property(env, exports, name, fn);
}

/* Module initialization sub-handlers */
void init_napi_kem(napi_env env, napi_value exports);
void init_napi_dsa(napi_env env, napi_value exports);
void init_napi_crypto(napi_env env, napi_value exports);
void init_napi_utils(napi_env env, napi_value exports);

#endif /* RIVIDE_NAPI_COMMON_H */
