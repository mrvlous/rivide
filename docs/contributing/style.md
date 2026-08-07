# Coding and License Style Guidelines

To maintain high code quality, security, and maintainability across the **Rivide** codebase, all contributions must adhere to the style and licensing standards outlined below.

---

## 1. C Standard & Formatting Rules

*   **C99 Compliance**: Code must compile cleanly under standard C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
*   **Indent & Column Limit**: 4-space indentation, no tabs, 100-character line length limit (enforced via `.clang-format`).
*   **Brace Style**: Attach opening braces (`BreakBeforeBraces: Attach`).
*   **Pointer Alignment**: Align pointer asterisk to the variable name (`uint8_t *buf`).

---

## 2. License Comment Header Rules

Every file in the repository must begin with the appropriate standardized MIT license header:

### Source Files (`.c`, `.h`), `CMakeLists.txt`, `Makefile`, `MAINTAINERS`, `CREDITS`, & `CHANGELOG.md`
Must include the standard 1-paragraph MIT license block:
```c
/*
 * SPDX-License-Identifier: MIT
 *
 * Rivide Post-Quantum Cryptography Library
 * Copyright (C) 2026 Moh. Ananda Firmansyah Putra
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */
```

### Configuration Files (`.clangd`, `.clang-format`, `.clang-tidy`, `.editorconfig`, `.gitattributes`, `.gitignore`)
Must include the 4-line concise copyright comment block:
```#
# SPDX-License-Identifier: MIT
#
# Rivide Post-Quantum Cryptography Library
# Copyright (C) 2026 Moh. Ananda Firmansyah Putra
```

### `LICENSE` File
Contains the full 3-paragraph MIT license text.
