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
# Orchestrates CMake configuration, compilation, automated testing, and installation.

# Directory layout paths
BUILD_DIR     := build
CMAKE_DIR     := .

# Project metadata and versioning
PROJECT_NAME  := rivide
VERSION       := 1.0.1
BUILD_TYPE    ?= Release

# Configurable build options
RIVIDE_BUILD_TESTS    ?= ON
RIVIDE_BUILD_EXAMPLES ?= ON

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

.PHONY: all help info check config build test examples run-examples bench install clean format check-format lint

.DEFAULT_GOAL := all

all: build ## Configure CMake and compile static/shared libraries, test suite, and examples

help: ## Display all available Makefile targets and descriptions
	@printf "$(CLR_BOLD)Rivide Post-Quantum Cryptography Build System$(CLR_RESET)  $(CLR_CYAN)v$(VERSION)$(CLR_RESET)\n\n"
	@printf "  $(CLR_BOLD)Usage$(CLR_RESET): make <target> [BUILD_TYPE=Release|Debug] [V=1] [COLOR=0]\n\n"
	@printf "$(CLR_BOLD)  Build Targets:$(CLR_RESET)\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "    $(CLR_CYAN)%-18s$(CLR_RESET) %s\n", $$1, $$2}'
	@printf "\n$(CLR_BOLD)  Variables:$(CLR_RESET)\n"
	@printf "    $(CLR_CYAN)BUILD_TYPE=Type$(CLR_RESET)   Set build configuration (Release or Debug)\n"
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
		-DRIVIDE_BUILD_EXAMPLES=$(RIVIDE_BUILD_EXAMPLES)
	$(Q)if [ -f $(BUILD_DIR)/compile_commands.json ]; then \
		ln -sf $(BUILD_DIR)/compile_commands.json compile_commands.json ; \
	fi
	$(Q)$(LOG_DONE) "CMake configuration complete."

build: config ## Compile all targets including static library, shared library, tests, and examples
	$(Q)$(LOG_INFO) "Compiling Rivide targets..."
	$(Q)$(CMAKE) --build $(BUILD_DIR) --config $(BUILD_TYPE) $(VERBOSE_FLAG)
	$(Q)$(LOG_DONE) "Compilation completed successfully."

test: build ## Run the automated unit test suite via CTest
	$(Q)$(LOG_INFO) "Running Rivide test suite..."
	$(Q)cd $(BUILD_DIR) && $(CTEST) --output-on-failure --verbose
	$(Q)$(LOG_DONE) "All unit tests passed."

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

bench: examples ## Compile and execute the PQC algorithm benchmark harness
	$(Q)$(LOG_INFO) "Executing PQC benchmark suite..."
	$(Q)./$(BUILD_DIR)/pqc_bench_example
	$(Q)$(LOG_DONE) "Benchmark completed."

install: build ## Install public headers and libraries to system/DESTDIR
	$(Q)$(LOG_INFO) "Installing Rivide libraries and public headers..."
	$(Q)$(CMAKE) --install $(BUILD_DIR)
	$(Q)$(LOG_DONE) "Installation complete."

clean: ## Remove build directory and generated compile_commands.json
	$(Q)$(LOG_INFO) "Cleaning build artifacts..."
	$(Q)rm -rf $(BUILD_DIR) compile_commands.json
	$(Q)$(LOG_DONE) "Clean finished."

format: ## Format all source, header, and test files using clang-format
	$(Q)$(LOG_INFO) "Formatting code with clang-format..."
	$(Q)clang-format -i $(shell find include src tests examples -type f \( -name "*.c" -o -name "*.h" \))
	$(Q)$(LOG_DONE) "Formatting complete."

check-format: ## Verify code formatting compliance without modifying files
	$(Q)$(LOG_INFO) "Checking code formatting compliance..."
	$(Q)clang-format --dry-run --Werror $(shell find include src tests examples -type f \( -name "*.c" -o -name "*.h" \))
	$(Q)$(LOG_DONE) "Code formatting is fully compliant."

lint: config ## Run static code analysis with clang-tidy
	$(Q)$(LOG_INFO) "Running static analysis with clang-tidy..."
	$(Q)clang-tidy -p $(BUILD_DIR) $(shell find src -type f -name "*.c")
	$(Q)$(LOG_DONE) "Static analysis finished."
