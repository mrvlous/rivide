<!--
SPDX-License-Identifier: MIT

Rivide Post-Quantum Cryptography Library
Copyright (C) 2026 Moh. Ananda Firmansyah Putra
-->

# Security: Constant-Time Engineering & Side-Channel Mitigation

This document details the constant-time coding disciplines, arithmetic techniques, timing side-channel countermeasures, and automated statistical timing leakage verification harnesses implemented in **Rivide**.

## 1. Principles of Constant-Time Implementation

To prevent timing side-channel attacks, execution time and instruction traces must remain strictly independent of all sensitive secret data (e.g. secret keys, error polynomials, random coins).

Rivide enforces three mandatory constant-time rules for secret-dependent paths:

1. **No Secret-Dependent Branching**: Prohibits `if`, `else`, `switch`, `? :`, and loop conditions that evaluate secret values.
2. **No Secret-Indexed Memory Lookups**: Prohibits array access using secret indices ($A[\text{secret}]$) to prevent cache-line timing attacks.
3. **No Variable-Time CPU Instructions**: Avoids integer division (`/`), remainder (`%`), and variable-latency barrel rotations on architectures where timing depends on operand magnitude.

## 2. Constant-Time Primitives in Rivide

### Constant-Time Memory Comparison (`rivide_ct_memcmp`)

Standard `memcmp` returns early upon finding the first differing byte, leaking the position of mismatches:

```c
int rivide_ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (pa[i] ^ pb[i]);
    }

    return (int)diff;
}
```

This ensures that comparison latency is identical regardless of where mismatches occur.

### Constant-Time Multiplexer (`rivide_ct_select`)

Selects between two byte buffers based on a mask without conditional branching:

```c
void rivide_ct_select(uint8_t *dest, const uint8_t *a, const uint8_t *b, size_t len, uint8_t mask) {
    for (size_t i = 0; i < len; i++) {
        dest[i] = b[i] ^ (mask & (a[i] ^ b[i]));
    }
}
```

## 3. Statistical Timing Leakage Verification (Dudect Methodology)

To experimentally prove the absence of timing side-channels, Rivide includes a dedicated statistical timing leakage verification harness under [`tests/timing/test_dudect_kem.c`](../../tests/timing/test_dudect_kem.c) based on the **Dudect** methodology (Welch's two-sample t-test).

### Test Methodology

1. **Two-Class Input Partitioning**:
   - **Class 0 (Fixed / Valid)**: Legitimate cryptographic inputs (e.g. valid ML-KEM-768 ciphertext, identical memory buffers).
   - **Class 1 (Random / Corrupted)**: Crafted or corrupted inputs designed to trigger internal verification failure or implicit rejection.
2. **Interleaved Sampling**:
   - In each iteration, a hardware random coin selects Class 0 or Class 1.
   - High-precision CPU timestamps (`rdtsc` / monotonic clock) record the start and completion timestamps.
3. **Online Welford Accumulation**:
   - Sample mean ($\bar{x}$) and sample variance ($s^2$) are calculated on-the-fly without heap allocations (0 Malloc).
4. **Welch's t-Statistic Evaluation**:
   $$t = \frac{\bar{x}_0 - \bar{x}_1}{\sqrt{\frac{s_0^2}{n_0} + \frac{s_1^2}{n_1}}}$$
   - **Null Hypothesis ($H_0$)**: Execution distributions of Class 0 and Class 1 are identical.
   - **Threshold**: $|t| < 4.5$. A value below $4.5$ proves with $p > 10^{-5}$ confidence that no statistically significant timing difference exists.

### Executing Timing Verification

```bash
make timing
# or
make dudect
```
