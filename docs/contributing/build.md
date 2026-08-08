<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Building, Testing & Tooling

This document describes the build pipeline, CMake targets, Makefile automation rules, unit test execution, and static analysis tools.

---

## 1. Master Makefile Automation Targets

The master [`Makefile`](../../Makefile) wraps CMake configuration and build steps:

| Target | Description |
| :--- | :--- |
| `make all` | Configure CMake and compile static library (`librivide.a`), test harness, and examples. |
| `make build` | Compile library targets, unit tests, and demonstration executables. |
| `make test` | Execute the unit test suite via CTest (`ctest --output-on-failure`). |
| `make run-examples` | Build and run ML-KEM and ML-DSA demonstration binaries. |
| `make format` | Auto-format all C source files and headers using `.clang-format`. |
| `make check-format` | Verify code formatting against `.clang-format` rules without modifying files. |
| `make lint` | Run static code analysis using `clang-tidy`. |
| `make check` | Check system for required dependencies (`cmake`, `gcc`, `ctest`, `clang-format`, `clang-tidy`). |
| `make clean` | Remove `build/` output directory and temporary build artifacts. |

---

## 2. Command Examples

```bash
# Verify system dependencies
make check

# Build library, tests, and run examples
make run-examples

# Execute unit tests
make test

# Format code and check compliance
make format && make check-format
```
