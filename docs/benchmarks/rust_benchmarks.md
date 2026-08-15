<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Benchmarks: Rust Crate Performance Suite

Instructions for executing high-precision Rust benchmarks.

---

## 1. Execution

From repository root:

```bash
make rust-bench
```

Or within `bindings/rust/`:

```bash
cd bindings/rust
cargo bench
```

Or standalone executable example:

```bash
cargo run --release --example bench
```
