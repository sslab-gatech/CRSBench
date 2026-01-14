# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: oom-harness
- **Vulnerability Type**: Heap buffer overflow (off-by-one error)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability created for stress testing)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: utils.c:24:21
- **Vulnerable Function**: buffer_write
- **DEDUP Token**: buffer_write--func_oom--LLVMFuzzerTestOneInput

### Stack Trace
```
WRITE of size 1 at 0x5120000005ec thread T0
    #0 0x5632e19f087d in buffer_write /src/cp-user-stress-test-src/utils.c:24:21
    #1 0x5632e19f065d in func_oom /src/cp-user-stress-test-src/oom-harness.c:24:9
    #2 0x5632e19f065d in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/oom-harness.c:45:5
```

The crash occurs when writing 1 byte to address 0x5120000005ec, which is **0 bytes after** a 300-byte region allocated at 0x5120000004c0. This indicates a classic off-by-one heap buffer overflow where the code attempts to write at index 300 of a 300-byte buffer (valid indices are 0-299).

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 21-21
- **Column Range**: 8-27

### Code Context
```c
void buffer_write(buffer_t *buf, size_t index, char byte) {
    if (index > buf->size) {  // Line 21 - VULNERABLE: Should be >=
        return;
    }
    buf->buf[index] = byte;   // Line 24 - Crash site
}
```

**Note**: The crash occurs at line 24 where the actual write happens, but the **root cause** is at line 21 where the bounds check uses the wrong comparison operator (`>` instead of `>=`). This is confirmed by the patch which fixes line 21.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-193**: Off-by-one Error

## Vulnerability Description

This is a classic **off-by-one error** in the `buffer_write` function in `utils.c`. The vulnerability exists in the bounds checking logic:

**Root Cause**: The bounds check at line 21 uses `if (index > buf->size)` which allows index values equal to `buf->size` to pass through. For a buffer of size 300, valid indices are 0-299, but this check allows index 300, causing a 1-byte write beyond the allocated buffer.

**Trigger Condition**: The harness (`oom-harness.c`) triggers this vulnerability when specific arithmetic constraints are met:
- `input->a * input->b == 0x1337 * 0x1338`
- `input->a + input->b == 0x1337 + 0x1338`

When these conditions are satisfied, the code calls `buffer_write(buf, input->c, 'a')` where `input->c` (300 or 0x12c) causes the off-by-one overflow.

**Impact**: This allows writing one byte past the end of a heap-allocated buffer, which can:
- Corrupt heap metadata
- Overwrite adjacent heap objects
- Lead to potential arbitrary code execution in exploitable scenarios

## POV Analysis

The POV blob contains 12 bytes:
```
Hex: 37 13 00 00 38 13 00 00 2c 01 00 00
```

Interpreted as `InputFormat` structure (3 integers):
- `input->a = 0x1337` (4919 decimal)
- `input->b = 0x1338` (4920 decimal)  
- `input->c = 0x012c` (300 decimal)

This input satisfies the arithmetic constraints in the harness and provides index 300 to `buffer_write`, triggering the off-by-one overflow in the 300-byte buffer.

## Patch Analysis

The patch fixes the root cause by correcting the bounds check:

```diff
-    if (index > buf->size) {
+    if (index >= buf->size) {
```

This change ensures that index values equal to or greater than `buf->size` are rejected, properly enforcing that only indices 0 to `buf->size - 1` are allowed.

**Patch Location**: utils.c, line 21 (the root cause location)

The fix is minimal and correct - it changes the comparison operator from `>` to `>=`, preventing writes at index equal to the buffer size.

## Recommendations
- **Suggested CWEs**: [CWE-193, CWE-122, CWE-787]
- **Vulnerability Name**: Off-by-one heap buffer overflow in buffer_write
- **Severity**: High (heap corruption vulnerability)
- **Classification**: This is a **synthetic** vulnerability created for stress testing CRS systems, not a real-world 1-day vulnerability