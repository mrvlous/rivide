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

# Master Build System Architecture
# Orchestrates CMake configuration, compilation, automated testing, KAT, benchmarks, and installation.

# Directory layout paths
BUILD_DIR     := build
CMAKE_DIR     := .

# Project metadata and versioning
PROJECT_NAME  := rivide
VERSION       := 1.1.4
BUILD_TYPE    ?= Release

# Configurable build options
RIVIDE_BUILD_TESTS      ?= ON
RIVIDE_BUILD_KAT        ?= ON
RIVIDE_BUILD_TIMING     ?= ON
RIVIDE_BUILD_BENCHMARKS ?= ON
RIVIDE_BUILD_EXAMPLES   ?= ON

# Toolchain executables
CMAKE         := cmake
CTEST         := ctest
CC            := gcc

# Verbose mode configuration: set V=1 to display raw build commands
ifeq ($(V),1)
    VERBOSE_FLAG := VERBOSE=1
    Q            :=
else
    VERBOSE_FLAG :=
    Q            := @
endif

# Terminal styling and color constants
ifeq ($(COLOR),0)
    CLR_RESET   :=
    CLR_BOLD    :=
    CLR_GREEN   :=
    CLR_YELLOW  :=
    CLR_BLUE    :=
    CLR_MAGENTA :=
    CLR_CYAN    :=
    CLR_RED     :=
else
    CLR_RESET   := \033[0m
    CLR_BOLD    := \033[1m
    CLR_GREEN   := \033[32m
    CLR_YELLOW  := \033[33m
    CLR_BLUE    := \033[34m
    CLR_MAGENTA := \033[35m
    CLR_CYAN    := \033[36m
    CLR_RED     := \033[31m
endif

# Formatted console logging helpers
LOG_INFO    := printf "  $(CLR_CYAN)$(CLR_BOLD)[INFO]$(CLR_RESET)  %s\n"
LOG_DONE    := printf "$(CLR_GREEN)$(CLR_BOLD)[DONE]$(CLR_RESET)  %s\n"
LOG_WARN    := printf "$(CLR_YELLOW)$(CLR_BOLD)[WARN]$(CLR_RESET)  %s\n"
LOG_ERR     := printf "$(CLR_RED)$(CLR_BOLD)[ERR]$(CLR_RESET)   %s\n"
LOG_CHECK   := printf "  $(CLR_GREEN)$(CLR_BOLD)[OK]$(CLR_RESET)    %s\n"
LOG_MISS    := printf "  $(CLR_RED)$(CLR_BOLD)[MISS]$(CLR_RESET)  %s\n"

.PHONY: all help info check config build test kat run-kat timing dudect bench run-bench examples run-examples fuzz node-build node-test node-bench node-publish rust-build rust-test rust-examples rust-bench rust-pack rust-publish install clean format check-format lint

.DEFAULT_GOAL := all

all: build ## Configure CMake and compile static/shared libraries, test suite, KAT, benchmarks, and examples

help: ## Display all available Makefile targets and descriptions
	@printf "$(CLR_BOLD)Rivide Post-Quantum Cryptography Build System$(CLR_RESET)  $(CLR_CYAN)v$(VERSION)$(CLR_RESET)\n\n"
	@printf "  $(CLR_BOLD)Usage$(CLR_RESET): make <target> [BUILD_TYPE=Release|Debug] [V=1] [COLOR=0]\n\n"
	@printf "$(CLR_BOLD)  Build & Test Targets:$(CLR_RESET)\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "    $(CLR_CYAN)%-18s$(CLR_RESET) %s\n", $$1, $$2}'
	@printf "\n$(CLR_BOLD)  Variables:$(CLR_RESET)\n"
	@printf "    $(CLR_CYAN)BUILD_TYPE=Type$(CLR_RESET)   Set build configuration (Release or Debug)\n"
	@printf "    $(CLR_CYAN)BENCH_ITERS=N$(CLR_RESET)     Set iteration count for benchmarks (default: 100)\n"
	@printf "    $(CLR_CYAN)V=1$(CLR_RESET)             Enable verbose build output showing exact commands\n"
	@printf "    $(CLR_CYAN)COLOR=0$(CLR_RESET)         Disable colored output in terminal logs\n\n"

info: ## Display build configuration parameters and toolchain versions
	@printf "$(CLR_BOLD)Rivide Build System Information$(CLR_RESET)\n\n"
	@printf "  $(CLR_BOLD)Project Configuration$(CLR_RESET)\n"
	@printf "    Name         : $(CLR_CYAN)$(PROJECT_NAME)$(CLR_RESET)\n"
	@printf "    Version      : $(CLR_CYAN)$(VERSION)$(CLR_RESET)\n"
	@printf "    Build Type   : $(CLR_CYAN)$(BUILD_TYPE)$(CLR_RESET)\n"
	@printf "    Build Directory: $(CLR_CYAN)$(BUILD_DIR)$(CLR_RESET)\n\n"
	@printf "  $(CLR_BOLD)Toolchain Environment$(CLR_RESET)\n"
	@printf "    CMake        : $(CLR_CYAN)$(shell $(CMAKE) --version 2>/dev/null | head -1 || echo 'not found')$(CLR_RESET)\n"
	@printf "    Compiler     : $(CLR_CYAN)$(shell $(CC) --version 2>/dev/null | head -1 || echo 'not found')$(CLR_RESET)\n"
	@printf "    CTest        : $(CLR_CYAN)$(shell $(CTEST) --version 2>/dev/null | head -1 || echo 'not found')$(CLR_RESET)\n\n"

check: ## Check availability of required development tools and build dependencies
	@printf "$(CLR_BOLD)Checking Build Dependencies$(CLR_RESET)\n\n"
	@command -v $(CC) >/dev/null 2>&1 && $(LOG_CHECK) "C Compiler ($(CC))" || $(LOG_MISS) "C Compiler ($(CC))"
	@command -v $(CMAKE) >/dev/null 2>&1 && $(LOG_CHECK) "CMake Build System ($(CMAKE))" || $(LOG_MISS) "CMake ($(CMAKE))"
	@command -v clang-format >/dev/null 2>&1 && $(LOG_CHECK) "Code Formatter (clang-format)" || $(LOG_WARN) "clang-format (optional)"
	@command -v clang-tidy >/dev/null 2>&1 && $(LOG_CHECK) "Static Analyzer (clang-tidy)" || $(LOG_WARN) "clang-tidy (optional)"
	@printf "\n"

config: ## Generate CMake build system files inside the build directory
	$(Q)$(LOG_INFO) "Configuring CMake build system ($(BUILD_TYPE))..."
	$(Q)$(CMAKE) -B $(BUILD_DIR) -S $(CMAKE_DIR) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DRIVIDE_BUILD_TESTS=$(RIVIDE_BUILD_TESTS) \
		-DRIVIDE_BUILD_KAT=$(RIVIDE_BUILD_KAT) \
		-DRIVIDE_BUILD_TIMING=$(RIVIDE_BUILD_TIMING) \
		-DRIVIDE_BUILD_BENCHMARKS=$(RIVIDE_BUILD_BENCHMARKS) \
		-DRIVIDE_BUILD_EXAMPLES=$(RIVIDE_BUILD_EXAMPLES)
	$(Q)if [ -f $(BUILD_DIR)/compile_commands.json ]; then \
		ln -sf $(BUILD_DIR)/compile_commands.json compile_commands.json ; \
	fi
	$(Q)$(LOG_DONE) "CMake configuration complete."

build: config ## Compile all targets including static/shared libraries, tests, KAT, and benchmarks
	$(Q)$(LOG_INFO) "Compiling Rivide targets..."
	$(Q)$(CMAKE) --build $(BUILD_DIR) --config $(BUILD_TYPE) $(VERBOSE_FLAG)
	$(Q)$(LOG_DONE) "Compilation completed successfully."

test: build ## Run the automated unit test suite via CTest
	$(Q)$(LOG_INFO) "Running Rivide unit test suite..."
	$(Q)cd $(BUILD_DIR) && $(CTEST) --output-on-failure --verbose -R rivide_tests
	$(Q)$(LOG_DONE) "All unit tests passed."

kat: build ## Execute the NIST Known Answer Test (KAT) validation suite
	$(Q)$(LOG_INFO) "Executing NIST Known Answer Test (KAT) suite..."
	$(Q)./$(BUILD_DIR)/rivide_kat_tests
	$(Q)$(LOG_DONE) "All NIST KAT validation vectors passed."

run-kat: kat ## Alias for kat target

timing: build ## Execute Dudect constant-time statistical timing leakage verification
	$(Q)$(LOG_INFO) "Executing Dudect constant-time statistical timing verification..."
	$(Q)./$(BUILD_DIR)/rivide_timing_tests
	$(Q)$(LOG_DONE) "All statistical timing leakage tests passed."

dudect: timing ## Alias for timing target

bench: build ## Execute the dedicated PQC benchmark subsystem
	$(Q)$(LOG_INFO) "Executing dedicated Rivide benchmark subsystem..."
	$(Q)./$(BUILD_DIR)/rivide_bench
	$(Q)$(LOG_DONE) "Benchmark execution complete."

run-bench: bench ## Alias for bench target

examples: build ## Ensure all sub-directory example binaries are compiled

run-examples: examples ## Execute all sub-directory example binaries sequentially
	$(Q)$(LOG_INFO) "Executing basic_kem_example..."
	$(Q)./$(BUILD_DIR)/basic_kem_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing basic_dsa_example..."
	$(Q)./$(BUILD_DIR)/basic_dsa_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing hybrid_pqc_aead_example..."
	$(Q)./$(BUILD_DIR)/hybrid_pqc_aead_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing pqc_tls_handshake_example..."
	$(Q)./$(BUILD_DIR)/pqc_tls_handshake_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing pqc_secure_storage_example..."
	$(Q)./$(BUILD_DIR)/pqc_secure_storage_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing dsa_detached_signature_example..."
	$(Q)./$(BUILD_DIR)/dsa_detached_signature_example
	$(Q)printf "\n"
	$(Q)$(LOG_INFO) "Executing simd_vector_example..."
	$(Q)./$(BUILD_DIR)/simd_vector_example
	$(Q)printf "\n"
	$(Q)$(LOG_DONE) "All example binaries executed successfully."

fuzz: ## Build LLVM libFuzzer targets using Clang
	$(Q)$(LOG_INFO) "Configuring and compiling libFuzzer targets with Clang..."
	$(Q)$(CMAKE) -B $(BUILD_DIR)-fuzz -S $(CMAKE_DIR) \
		-DCMAKE_C_COMPILER=clang \
		-DRIVIDE_BUILD_FUZZERS=ON \
		-DCMAKE_BUILD_TYPE=Debug
	$(Q)$(CMAKE) --build $(BUILD_DIR)-fuzz $(VERBOSE_FLAG)
	$(Q)$(LOG_DONE) "Fuzzing targets compiled in $(BUILD_DIR)-fuzz/."

node-build: ## Build Node.js native bindings using node-gyp
	$(Q)$(LOG_INFO) "Building Node.js native bindings in bindings/node/..."
	$(Q)mkdir -p bindings/node/deps
	$(Q)cp -rf include src bindings/node/deps/
	$(Q)cd bindings/node && npx --yes node-gyp rebuild
	$(Q)$(LOG_DONE) "Node.js native bindings compiled."

node-test: node-build ## Run automated Node.js test suite
	$(Q)$(LOG_INFO) "Executing Node.js unit tests..."
	$(Q)cd bindings/node && node --test test/*.js
	$(Q)$(LOG_DONE) "Node.js unit tests passed."

node-bench: node-build ## Execute Node.js performance benchmarks
	$(Q)$(LOG_INFO) "Executing Node.js benchmark suite..."
	$(Q)cd bindings/node && node bench.js

node-publish: node-test ## Publish Node.js native addon to npm registry
	$(Q)$(LOG_INFO) "Publishing Node.js package to npm registry..."
	$(Q)cd bindings/node && npm publish --access public
	$(Q)$(LOG_DONE) "Node.js package published to npm successfully."

rust-build: ## Build Rust native bindings using cargo
	$(Q)$(LOG_INFO) "Building Rust native bindings in bindings/rust/..."
	$(Q)cd bindings/rust && cargo build --release
	$(Q)$(LOG_DONE) "Rust native bindings compiled."

rust-test: ## Run automated Rust integration tests and doctests
	$(Q)$(LOG_INFO) "Executing Rust test suite..."
	$(Q)cd bindings/rust && cargo test
	$(Q)$(LOG_DONE) "Rust test suite passed."

rust-examples: ## Execute Rust demonstration examples
	$(Q)$(LOG_INFO) "Executing Rust demonstration examples..."
	$(Q)cd bindings/rust && cargo run --example kem_exchange
	$(Q)cd bindings/rust && cargo run --example dsa_sign
	$(Q)cd bindings/rust && cargo run --example hybrid_channel
	$(Q)$(LOG_DONE) "All Rust demonstration examples executed successfully."

rust-bench: ## Execute Rust performance benchmarks
	$(Q)$(LOG_INFO) "Executing Rust benchmark suite..."
	$(Q)cd bindings/rust && cargo bench

rust-pack: ## Package Rust crate for crates.io with bundled C source
	$(Q)$(LOG_INFO) "Packaging Rust crate for crates.io..."
	$(Q)mkdir -p bindings/rust/c_src
	$(Q)cp -rf include src bindings/rust/c_src/
	$(Q)cd bindings/rust && cargo package --allow-dirty
	$(Q)rm -rf bindings/rust/c_src
	$(Q)$(LOG_DONE) "Rust crate packaged and verified successfully."

rust-publish: ## Publish Rust crate to crates.io with bundled C source
	$(Q)$(LOG_INFO) "Publishing Rust crate to crates.io..."
	$(Q)mkdir -p bindings/rust/c_src
	$(Q)cp -rf include src bindings/rust/c_src/
	$(Q)cd bindings/rust && cargo publish --allow-dirty
	$(Q)rm -rf bindings/rust/c_src
	$(Q)$(LOG_DONE) "Rust crate published to crates.io successfully."

install: build ## Install public headers and libraries to system/DESTDIR
	$(Q)$(LOG_INFO) "Installing Rivide libraries and public headers..."
	$(Q)$(CMAKE) --install $(BUILD_DIR)
	$(Q)$(LOG_DONE) "Installation complete."

clean: ## Remove build directories and generated compile_commands.json
	$(Q)$(LOG_INFO) "Cleaning build artifacts..."
	$(Q)rm -rf $(BUILD_DIR) $(BUILD_DIR)-fuzz compile_commands.json bindings/node/build bindings/node/deps bindings/rust/target bindings/rust/c_src
	$(Q)$(LOG_DONE) "Clean finished."

format: ## Format all C, Rust, and Node.js files using clang-format, rustfmt, and prettier
	$(Q)$(LOG_INFO) "Formatting C/H files with clang-format..."
	$(Q)clang-format -i $(shell find include src tests benchmarks examples fuzz bindings/node/src -type f \( -name "*.c" -o -name "*.h" \))
	$(Q)$(LOG_INFO) "Formatting Rust files with cargo fmt..."
	$(Q)cd bindings/rust && cargo fmt
	$(Q)$(LOG_INFO) "Formatting Node.js files with prettier..."
	$(Q)cd bindings/node && npx --yes prettier --write .
	$(Q)$(LOG_DONE) "Formatting complete across C, Rust, and Node.js."

check-format: ## Verify code formatting compliance across C, Rust, and Node.js without modifying files
	$(Q)$(LOG_INFO) "Checking C code formatting compliance..."
	$(Q)clang-format --dry-run --Werror $(shell find include src tests benchmarks examples fuzz bindings/node/src -type f \( -name "*.c" -o -name "*.h" \))
	$(Q)$(LOG_INFO) "Checking Rust formatting compliance..."
	$(Q)cd bindings/rust && cargo fmt -- --check
	$(Q)$(LOG_INFO) "Checking Node.js formatting compliance..."
	$(Q)cd bindings/node && npx --yes prettier --check .
	$(Q)$(LOG_DONE) "Code formatting is fully compliant across C, Rust, and Node.js."

lint: config ## Run static code analysis with clang-tidy
	$(Q)$(LOG_INFO) "Running static analysis with clang-tidy..."
	$(Q)clang-tidy -p $(BUILD_DIR) $(shell find src benchmarks -type f -name "*.c")
