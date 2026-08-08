<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Development Environment Setup

This document describes how to set up your local development environment, toolchain packages, CMake build utilities, and IDE code intelligence for contributing to **Rivide**.

---

## 1. Required Dependencies

To compile, test, and format the codebase, install the following packages:

### Debian / Ubuntu Linux
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ctest clang-format clang-tidy clangd
```

### Arch Linux / Manjaro
```bash
sudo pacman -S --needed base-devel cmake clang
```

---

## 2. IDE & Code Intelligence Setup

Rivide includes native support for `clangd` (the LLVM Language Server Protocol server) to provide error-free autocompletion, real-time diagnostic reporting, and symbol navigation across VS Code, Neovim, CLion, and Antigravity IDE.

### Automatic Compilation Database Generation
When building via `make` or CMake, a `compile_commands.json` database is automatically placed in the project root:
```bash
make config
```
This enables `.clangd` to immediately index all include directories (`-Iinclude`), C99 standard flags (`-std=c99`), and compiler warnings without any manual IDE configuration.
