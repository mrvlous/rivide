# In-Depth Build System Guide

This guide details compilation workflow, CMake configuration parameters, and Makefile automation targets available in **Rivide**.

## Building via Makefile

The repository includes a top-level Makefile for convenient developer workflows:

```bash
# Compile static/shared libraries, tests, KAT, benchmarks, and examples
make build

# Run automated unit test suite
make test

# Execute NIST Known Answer Test (KAT) validation suite
make kat

# Compile and execute dedicated PQC performance benchmark subsystem
make bench

# Compile and execute all example binaries
make run-examples

# Compile LLVM libFuzzer targets using Clang
make fuzz CC=clang

# Check code formatting compliance
make check-format

# Format all code with clang-format
make format

# Run static analysis with clang-tidy
make lint

# Clean build directory and compile commands
make clean
```

## Configurable Build Variables

Build parameters can be overridden on the command line:

```bash
# Build in Debug configuration with symbols enabled
make build BUILD_TYPE=Debug

# Show verbose raw build commands
make build V=1

# Disable colored terminal log output
make build COLOR=0
```

## Direct CMake Invocation

For custom build trees, CMake can be invoked directly:

```bash
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DRIVIDE_BUILD_TESTS=ON \
  -DRIVIDE_BUILD_EXAMPLES=ON

make -j$(nproc)
ctest --output-on-failure
```

## CMake Configuration Flags

| CMake Option | Default | Description |
| :--- | :--- | :--- |
| `CMAKE_BUILD_TYPE` | `Release` | Build configuration (`Release` or `Debug`). |
| `RIVIDE_BUILD_TESTS` | `ON` | Enable compilation of `rivide_tests` binary. |
| `RIVIDE_BUILD_EXAMPLES` | `ON` | Enable compilation of sub-directory example binaries. |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library (`librivide.so`) in addition to static library (`librivide.a`). |
