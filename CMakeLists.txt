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
project(rivide VERSION 0.1.0 LANGUAGES C)

# Export compilation commands database for clangd, IDEs, and linters
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C Language Standard Configuration
# Enforce strict compliance with the ISO C99 standard without compiler extensions.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler Warning and Security Configurations
# Enable strict diagnostic warnings and treat all compiler warnings as errors when using GCC or Clang.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -fno-strict-aliasing)
endif()

# Core Library Source Definitions
# List all source code files required to compile the static library archive.
set(RIVIDE_SOURCES
    src/core/rivide_init.c
    src/core/rivide_types.c
    src/utils/mem.c
    src/utils/random.c
    src/crypto/sha3.c
    src/crypto/aes_gcm.c
    src/pqc/ml_kem.c
    src/pqc/ml_dsa.c
)

# Static Library Target Specification
# Configure the static target and define header search paths for build and installation environments.
add_library(rivide STATIC ${RIVIDE_SOURCES})
target_include_directories(rivide
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Installation Rules and Target Deployment
# Define standard installation destinations for library binaries and header files using GNUInstallDirs.
include(GNUInstallDirs)
install(TARGETS rivide
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/rivide
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Automated Test Suite Configuration
# Compile and link the unit testing binary when RIVIDE_BUILD_TESTS is enabled.
option(RIVIDE_BUILD_TESTS "Build test suite" ON)
if(RIVIDE_BUILD_TESTS)
    enable_testing()
    add_executable(rivide_tests
        tests/test_main.c
        tests/test_ml_kem.c
        tests/test_ml_dsa.c
    )
    target_link_libraries(rivide_tests PRIVATE rivide)
    target_include_directories(rivide_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_test(NAME rivide_tests COMMAND rivide_tests)
endif()

# Example Programs Building Configuration
# Compile demonstration executables showcasing ML-KEM and ML-DSA cryptographic operations.
option(RIVIDE_BUILD_EXAMPLES "Build example programs" ON)
if(RIVIDE_BUILD_EXAMPLES)
    add_executable(basic_kem_example examples/basic_kem_example.c)
    target_link_libraries(basic_kem_example PRIVATE rivide)
    target_include_directories(basic_kem_example PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_executable(basic_dsa_example examples/basic_dsa_example.c)
    target_link_libraries(basic_dsa_example PRIVATE rivide)
    target_include_directories(basic_dsa_example PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
endif()
