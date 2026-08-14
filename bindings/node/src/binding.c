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
 * @file binding.c
 * @brief Node-API main entry point and module export registration.
 */

#include "napi_common.h"

static napi_value init_rivide_addon(napi_env env, napi_value exports) {
    if (rivide_init() != RIVIDE_SUCCESS) {
        THROW_ERROR(env, "Failed to initialize Rivide cryptographic engine");
    }

    init_napi_kem(env, exports);
    init_napi_dsa(env, exports);
    init_napi_crypto(env, exports);
    init_napi_utils(env, exports);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_rivide_addon)
