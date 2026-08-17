# SPDX-License-Identifier: MIT
#
# Rivide Post-Quantum Cryptography Library
# Copyright (C) 2026 Moh. Ananda Firmansyah Putra
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

cmake_minimum_required(VERSION 3.10)
project(rivide VERSION 1.1.3 LANGUAGES C)

# Export compilation commands database for clangd, IDEs, and linters
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C Language Standard Configuration
# Enforce strict compliance with the ISO C99 standard without compiler extensions.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler Warning and Security Configurations
# Enable strict diagnostic warnings and treat all compiler warnings as errors.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -fno-strict-aliasing)
    if(APPLE)
        add_compile_definitions(_DARWIN_C_SOURCE)
    elseif(UNIX)
        add_compile_definitions(_POSIX_C_SOURCE=200809L)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /WX)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# Core Library Source Definitions
# List all super-modular source code files required to compile the library.
set(RIVIDE_SOURCES
    src/core/rivide_init.c
    src/core/rivide_types.c
    src/utils/mem.c
    src/utils/random.c
    src/crypto/aes_core.c
    src/crypto/aes_gcm.c
    src/crypto/ghash.c
    src/crypto/keccak.c
    src/crypto/sha3.c
    src/pqc/ntt_simd.c
    src/pqc/ml_kem/kem_reduce.c
    src/pqc/ml_kem/kem_ntt.c
    src/pqc/ml_kem/kem_poly.c
    src/pqc/ml_kem/kem_cbd.c
    src/pqc/ml_kem/kem_compress.c
    src/pqc/ml_kem/kem_encode.c
    src/pqc/ml_kem/kem_sampling.c
    src/pqc/ml_kem/ml_kem.c
    src/pqc/ml_dsa/dsa_reduce.c
    src/pqc/ml_dsa/dsa_ntt.c
    src/pqc/ml_dsa/dsa_poly.c
    src/pqc/ml_dsa/dsa_rounding.c
    src/pqc/ml_dsa/dsa_packing.c
    src/pqc/ml_dsa/dsa_sampling.c
    src/pqc/ml_dsa/ml_dsa.c
)

# Static and Shared Library Targets Specification
add_library(rivide STATIC ${RIVIDE_SOURCES})
set_property(TARGET rivide PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(rivide
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

add_library(rivide_shared SHARED ${RIVIDE_SOURCES})
set_target_properties(rivide_shared PROPERTIES OUTPUT_NAME "rivide")
target_include_directories(rivide_shared
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Platform-specific link dependencies
if(WIN32)
    target_link_libraries(rivide PUBLIC bcrypt)
    target_link_libraries(rivide_shared PRIVATE bcrypt)
endif()

# Installation Rules and Target Deployment
include(GNUInstallDirs)
install(TARGETS rivide rivide_shared
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/rivide
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
    PATTERN "internal" EXCLUDE
)

# Pkg-config File Generation & Deployment
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/rivide.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/rivide.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rivide.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Automated Test Suite Configuration
option(RIVIDE_BUILD_TESTS "Build test suite" ON)
if(RIVIDE_BUILD_TESTS)
    enable_testing()
    add_executable(rivide_tests
        tests/test_main.c
        tests/pqc/test_ml_kem.c
        tests/pqc/test_ml_dsa.c
        tests/pqc/test_ntt.c
        tests/crypto/test_sha3.c
        tests/crypto/test_aes_gcm.c
        tests/utils/test_mem.c
    )
    target_link_libraries(rivide_tests PRIVATE rivide)
    target_include_directories(rivide_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    add_test(NAME rivide_tests COMMAND rivide_tests)
endif()

# NIST Known Answer Test (KAT) Suite Configuration
option(RIVIDE_BUILD_KAT "Build NIST Known Answer Test (KAT) suite" ON)
if(RIVIDE_BUILD_KAT)
    add_executable(rivide_kat_tests
        tests/kat/test_kat_main.c
        tests/kat/test_kat_sha3.c
        tests/kat/test_kat_ml_kem.c
        tests/kat/test_kat_ml_dsa.c
    )
    target_link_libraries(rivide_kat_tests PRIVATE rivide)
    target_include_directories(rivide_kat_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/kat
    )
    add_test(NAME rivide_kat_tests COMMAND rivide_kat_tests)
endif()

# Constant-Time Statistical Timing Leakage Subsystem (Dudect)
option(RIVIDE_BUILD_TIMING "Build constant-time statistical timing leakage harness" ON)
if(RIVIDE_BUILD_TIMING)
    add_executable(rivide_timing_tests
        tests/timing/test_dudect_kem.c
    )
    target_link_libraries(rivide_timing_tests PRIVATE rivide)
    if(UNIX AND NOT APPLE)
        target_link_libraries(rivide_timing_tests PRIVATE m)
    endif()
    target_include_directories(rivide_timing_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/timing
    )
    add_test(NAME rivide_timing_tests COMMAND rivide_timing_tests)
endif()

# Dedicated Benchmark Subsystem Configuration
option(RIVIDE_BUILD_BENCHMARKS "Build dedicated benchmark subsystem" ON)
if(RIVIDE_BUILD_BENCHMARKS)
    add_executable(rivide_bench
        benchmarks/bench_main.c
        benchmarks/bench_kem.c
        benchmarks/bench_dsa.c
        benchmarks/bench_crypto.c
    )
    target_link_libraries(rivide_bench PRIVATE rivide)
    target_include_directories(rivide_bench PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks
    )
endif()

# Sub-directory Example Executables Configuration
option(RIVIDE_BUILD_EXAMPLES "Build example programs" ON)
if(RIVIDE_BUILD_EXAMPLES)
    add_executable(basic_kem_example examples/basic/kem_encapsulation.c)
    target_link_libraries(basic_kem_example PRIVATE rivide)
    target_include_directories(basic_kem_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(basic_dsa_example examples/basic/dsa_digital_signature.c)
    target_link_libraries(basic_dsa_example PRIVATE rivide)
    target_include_directories(basic_dsa_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(hybrid_pqc_aead_example examples/hybrid/pqc_aead_channel.c)
    target_link_libraries(hybrid_pqc_aead_example PRIVATE rivide)
    target_include_directories(hybrid_pqc_aead_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(pqc_tls_handshake_example examples/protocol/tls_handshake_pqc.c)
    target_link_libraries(pqc_tls_handshake_example PRIVATE rivide)
    target_include_directories(pqc_tls_handshake_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(pqc_secure_storage_example examples/storage/secure_vault_storage.c)
    target_link_libraries(pqc_secure_storage_example PRIVATE rivide)
    target_include_directories(pqc_secure_storage_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(dsa_detached_signature_example examples/document/detached_pdf_signer.c)
    target_link_libraries(dsa_detached_signature_example PRIVATE rivide)
    target_include_directories(dsa_detached_signature_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(simd_vector_example examples/simd/vector_acceleration.c)
    target_link_libraries(simd_vector_example PRIVATE rivide)
    target_include_directories(simd_vector_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif()

# LLVM libFuzzer Fuzzing Targets Configuration
option(RIVIDE_BUILD_FUZZERS "Build libFuzzer fuzzing targets" OFF)
if(RIVIDE_BUILD_FUZZERS)
    add_library(rivide_fuzz STATIC ${RIVIDE_SOURCES})
    target_include_directories(rivide_fuzz PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(rivide_fuzz PRIVATE -fsanitize=fuzzer-no-link,address,undefined -g)
    endif()

    set(FUZZ_TARGETS
        fuzz_ml_kem_decaps
        fuzz_ml_dsa_verify
        fuzz_aes_gcm
        fuzz_sha3
    )
    foreach(TARGET ${FUZZ_TARGETS})
        add_executable(${TARGET} fuzz/${TARGET}.c)
        target_link_libraries(${TARGET} PRIVATE rivide_fuzz)
        target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_options(${TARGET} PRIVATE -fsanitize=fuzzer,address,undefined -g)
        target_link_options(${TARGET} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
