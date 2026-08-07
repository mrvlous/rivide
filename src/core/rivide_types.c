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
 * @file rivide_types.c
 * @brief Error code to human-readable string mappings.
 */

#include "rivide/rivide_types.h"

const char *rivide_status_str(rivide_status_t status) {
    switch (status) {
    case RIVIDE_SUCCESS:
        return "success";
    case RIVIDE_ERR_NULL_PTR:
        return "null pointer argument";
    case RIVIDE_ERR_INVALID_PARAM:
        return "invalid parameter";
    case RIVIDE_ERR_RNG_FAILURE:
        return "random number generator failure";
    case RIVIDE_ERR_VERIFICATION_FAILED:
        return "signature verification failed";
    case RIVIDE_ERR_DECAPSULATION_FAILED:
        return "decapsulation failed";
    case RIVIDE_ERR_UNSUPPORTED:
        return "unsupported feature";
    case RIVIDE_ERR_INTERNAL:
        return "internal error";
    default:
        return "unknown error";
    }
}
