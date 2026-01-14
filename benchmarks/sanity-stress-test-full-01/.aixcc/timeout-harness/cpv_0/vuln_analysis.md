# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: timeout-harness
- **Vulnerability Type**: Heap buffer overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: utils.c:24
- **Vulnerable Function**: buffer_write
- **DEDUP Token**: buffer_write--func_timeout--LLVMFuzzerTestOneInput

### Stack Trace
```
==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5120000005ec at pc 0x55b87a91789e bp 0x7ffe1140eb10 sp 0x7ffe1140eb08
WRITE of size 1 at 0x5120000005ec thread T0
    #0 0x55b87a91789d in buffer_write /src/cp-user-stress-test-src/utils.c:24:21
    #1 0x55b87a917679 in func_timeout /src/cp-user-stress-test-src/timeout-harness.c:22:9
    #2 0x55b87a917679 in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/timeout-harness.c:34:5
```

The crash occurs when writing 1 byte at address `0x5120000005ec`, which is **0 bytes after** a 300-byte buffer region `[0x5120000004c0,0x5120000005ec)`.

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause)
- **Type**: Both crash_site and root_cause (same location)
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 21-21
- **Column Range**: 8-26

### Code Context
```c
void buffer_write(buffer_t *buf, size_t index, char byte) {
    if (index > buf->size) {        // Line 21 - VULNERABLE: off-by-one error
        return;
    }
    buf->buf[index] = byte;         // Line 24 - Crash occurs here
}
```

**The Bug**: The bounds check on line 21 uses `index > buf->size` instead of `index >= buf->size`. This is a classic **off-by-one error** that allows writing to `buf->buf[buf->size]`, which is exactly one byte past the allocated buffer.

**The Trigger**: When `input->c` equals 300 (the buffer size), the condition `300 > 300` evaluates to false, allowing the write to proceed at `buf->buf[300]`, which is out of bounds.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-193**: Off-by-one Error

## Vulnerability Description

This is a **heap-based buffer overflow** caused by an **off-by-one error** in the bounds checking logic of the `buffer_write()` function.

**Root Cause**: The vulnerability exists in `utils.c` at line 21, where the bounds check incorrectly uses the condition `if (index > buf->size)` instead of `if (index >= buf->size)`. This allows an attacker to write one byte past the end of the allocated buffer when `index` equals exactly `buf->size`.

**Attack Scenario**: 
1. A 300-byte buffer is allocated via `buffer_create(300)`
2. Valid indices should be 0-299 (inclusive)
3. The flawed bounds check allows index=300 to pass through
4. Writing to `buf->buf[300]` corrupts heap metadata or adjacent data

**Impact**: This vulnerability can lead to heap corruption, potential code execution, or denial of service depending on what data lies adjacent to the buffer in memory.

## POV Analysis

The POV file (`pov_0.blob`) is a 12-byte input that satisfies the arithmetic constraints in the harness:

```
Hex dump: 37 13 00 00 38 13 00 00 2c 01 00 00
```

Interpreting as `InputFormat` struct (3 integers):
- `input->a` = 0x00001337 (4919)
- `input->b` = 0x00001338 (4920)  
- `input->c` = 0x0000012c (300)

The values satisfy the constraint: `a * b == 0x1337 * 0x1338` and `a + b == 0x1337 + 0x1338`, which triggers the vulnerable code path at line 22 of `timeout-harness.c`:

```c
buffer_write(buf, input->c, 'a');  // Writes to index 300, causing overflow
```

## Patch Analysis

The patch file (`patch_0.diff`) shows the fix:

```diff
-    if (index > buf->size) {
+    if (index >= buf->size) {
```

This changes the bounds check from "greater than" to "greater than or equal to", correctly preventing writes at `index == buf->size`. The patch confirms that both the **crash site** and **root cause** are at the same location (line 21 of `utils.c`).

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-787, CWE-193]
- **Vulnerability Name**: "Off-by-one heap buffer overflow in buffer_write"
- **Origin Classification**: synthetic (no CVE or official reference found)
- **Severity**: High (heap corruption with potential for exploitation)