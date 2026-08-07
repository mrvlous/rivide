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
VERSION       := 0.1.0
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

.PHONY: all help info check config build test examples run-examples install clean format check-format lint

.DEFAULT_GOAL := all

all: build ## Configure CMake and compile the static library, test suite, and examples

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

check: ## Verify that all required compilation dependencies are installed on the system
	@MISSING=0; \
	for tool in cmake gcc ctest clang-format clang-tidy; do \
	    if command -v $$tool >/dev/null 2>&1; then \
	        $(LOG_CHECK) "$$tool"; \
	    else \
	        $(LOG_MISS) "$$tool"; \
	        MISSING=$$((MISSING + 1)); \
	    fi; \
	done; \
	printf "\n"; \
	if [ $$MISSING -eq 0 ]; then \
	    $(LOG_DONE) "All build dependencies are satisfied"; \
	else \
	    $(LOG_WARN) "$$MISSING optional build dependencies are missing"; \
	fi

config: ## Generate CMake build scripts and export compilation database for clangd
	@$(LOG_INFO) "Configuring CMake build scripts ($(BUILD_TYPE))..."
	$(Q)$(CMAKE) -B $(BUILD_DIR) -S $(CMAKE_DIR) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DRIVIDE_BUILD_TESTS=$(RIVIDE_BUILD_TESTS) \
		-DRIVIDE_BUILD_EXAMPLES=$(RIVIDE_BUILD_EXAMPLES)
	$(Q)if [ -f $(BUILD_DIR)/compile_commands.json ]; then \
		ln -sf $(BUILD_DIR)/compile_commands.json compile_commands.json 2>/dev/null || true; \
	fi

build: config ## Compile static library, unit test binaries, and example executables
	@$(LOG_INFO) "Compiling Rivide cryptographic library targets..."
	$(Q)$(CMAKE) --build $(BUILD_DIR) $(VERBOSE_FLAG)
	@$(LOG_DONE) "Compilation completed successfully"

test: build ## Run automated unit tests using CTest
	@$(LOG_INFO) "Executing unit test suite..."
	$(Q)cd $(BUILD_DIR) && $(CTEST) --output-on-failure
	@$(LOG_DONE) "All unit tests executed successfully"

examples: build ## Ensure example targets are built
	@$(LOG_INFO) "Example targets compiled"

run-examples: build ## Build and execute ML-KEM and ML-DSA demonstration programs
	@$(LOG_INFO) "Running ML-KEM example application..."
	$(Q)./$(BUILD_DIR)/basic_kem_example || true
	@$(LOG_INFO) "Running ML-DSA example application..."
	$(Q)./$(BUILD_DIR)/basic_dsa_example || true
	@$(LOG_DONE) "Example applications executed"

install: build ## Install library archives and header files to system locations
	@$(LOG_INFO) "Installing Rivide artifacts..."
	$(Q)$(CMAKE) --install $(BUILD_DIR)
	@$(LOG_DONE) "Installation complete"

clean: ## Remove build outputs, object files, and temporary artifacts
	@$(LOG_INFO) "Cleaning build artifacts..."
	$(Q)rm -rf $(BUILD_DIR) compile_commands.json
	@$(LOG_DONE) "Clean completed successfully"

format: ## Format C source files and header files using clang-format
	@$(LOG_INFO) "Formatting C source files using .clang-format..."
	$(Q)find src include tests examples -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format -i {} + 2>/dev/null || true
	@$(LOG_DONE) "Source formatting completed"

check-format: ## Verify code formatting against .clang-format rules without modifying files
	@$(LOG_INFO) "Verifying code formatting..."
	$(Q)find src include tests examples -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format --dry-run -Werror {} + 2>/dev/null || (echo "$(CLR_RED)[FAIL] Code formatting check failed. Run 'make format' to fix.$(CLR_RESET)" && exit 1)
	@$(LOG_DONE) "Code formatting is compliant"

lint: config ## Execute static code analysis using clang-tidy
	@$(LOG_INFO) "Linting C source files with clang-tidy..."
	$(Q)find src -type f -name "*.c" -exec clang-tidy -p=$(BUILD_DIR) {} \; 2>/dev/null || true
	@$(LOG_DONE) "Linting analysis completed"
