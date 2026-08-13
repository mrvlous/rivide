# Coding Style & Memory Standards Guide

This guide establishes the mandatory coding style, memory safety constraints, and Doxygen documentation conventions for contributions to Rivide.

## Core Rules

1. **Strict ISO C99 Standard**:
   - Use `-std=c99` without non-standard compiler extensions.
   - Use standard fixed-width integer types (`uint8_t`, `uint32_t`, `int16_t`, `uint64_t`).

2. **Zero Dynamic Allocation (0 Malloc)**:
   - **NEVER** use `malloc()`, `calloc()`, `realloc()`, or `free()`.
   - Allocate data buffers on the stack or accept caller-supplied pointers.

3. **No Prohibited Comment Banners**:
   - **NEVER** use ASCII divider lines such as `===` or `---` in comments or documentation.
   - Use clean, minimal comment blocks.

4. **Doxygen Documentation Standard**:
   - Public and internal functions MUST include `@brief`, `@param`, and `@return` tags in formal English.

```c
/**
 * @brief Compress a single coefficient from Z_q to d bits.
 *
 * @param[in] x Coefficient in [0, q-1].
 * @param[in] d Target bit length.
 * @return Compressed d-bit integer value.
 */
uint16_t compress_coeff(int16_t x, int d);
```

5. **Formatting Enforcement**:
   - All code must pass `make check-format` (`clang-format --dry-run --Werror`).
