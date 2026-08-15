# Developer Environment Setup Guide

This guide describes how to configure your local development workspace to build, test, format, and contribute to the **Rivide Post-Quantum Cryptography Library**.

## System Prerequisites

To build and test Rivide, your system requires:

1. **C Compiler**:
   - `gcc` ($\ge 7.0$) or `clang` ($\ge 6.0$) supporting ISO C99.
2. **Build Toolchain**:
   - `cmake` ($\ge 3.16$)
   - `make` (GNU Make $\ge 3.82$)
3. **Language Bindings Toolchains (Optional)**:
   - **Node.js**: `node` ($\ge 16.0$) and `npm` for JavaScript/TypeScript native addon.
   - **Rust**: `rustc` and `cargo` ($\ge 1.70$) for Rust native crate.
4. **Quality & Formatting Tools (Optional but Recommended)**:
   - `clang-format` ($\ge 10.0$)
   - `clang-tidy` ($\ge 10.0$)

## Linux / Ubuntu / Debian Installation

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake gcc clang clang-format clang-tidy
```

## macOS Installation

```bash
brew install cmake gcc llvm clang-format
```

## Verifying Toolchain Dependencies

Run `make check` from the repository root:

```bash
make check
```

Output:
```text
Checking Build Dependencies

  [OK]    C Compiler (gcc)
  [OK]    CMake Build System (cmake)
  [OK]    Code Formatter (clang-format)
  [OK]    Static Analyzer (clang-tidy)
```
