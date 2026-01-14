# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: longjmp-harness
- **Vulnerability Type**: heap-buffer-overflow (off-by-one error)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: utils.c:24:21
- **Vulnerable Function**: buffer_write
- **DEDUP Token**: buffer_write--func_longjmp--LLVMFuzzerTestOneInput

### Stack Trace
```
#0 0x55b8e40b183d in buffer_write /src/cp-user-stress-test-src/utils.c:24:21
#1 0x55b8e40b1522 in func_longjmp /src/cp-user-stress-test-src/longjmp-harness.c:30:9
#2 0x55b8e40b164f in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/longjmp-harness.c:51:5
```

### Memory Details
- **WRITE of size 1** at address 0x5120000005ec
- Buffer allocated: 300-byte region [0x5120000004c0, 0x5120000005ec)
- The write occurs at 0x5120000005ec, which is **0 bytes after** the allocated region (off-by-one)

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 24-24
- **Column Range**: 21-21

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 21-21
- **Column Range**: 9-28

### Code Context

**Vulnerable code in utils.c (before patch):**
```c
void buffer_write(buffer_t *buf, size_t index, char byte) {
    if (index > buf->size) {  // Line 21 - BUG: should be >=
        return;
    }
    buf->buf[index] = byte;   // Line 24 - Crash site
}
```

**The issue:**
- The bounds check on line 21 uses `>` instead of `>=`
- For a buffer of size 300, valid indices are 0-299
- The buggy check allows `index == 300` (when `index > 300` is false)
- Writing to `buf->buf[300]` accesses one byte past the allocated buffer

**Trigger condition (from longjmp-harness.c):**
```c
global_buf = buffer_create(300);  // Allocates 300 bytes (indices 0-299)

if (input->a * input->b == 0x1337 * 0x1338 &&
    input->a + input->b == 0x1337 + 0x1338) {
    buffer_write(global_buf, input->c, 'a');  // If input->c == 300, triggers overflow
}
```

## CWE Classification
- **CWE-193**: Off-by-one Error
- **CWE-787**: Out-of-bounds Write
- **CWE-122**: Heap-based Buffer Overflow

## Vulnerability Description

This is a classic **off-by-one error** in a bounds check that leads to a heap buffer overflow. The `buffer_write()` function in `utils.c` is designed to write a single byte to a buffer at a specified index, but the bounds validation is incorrect.

**Root Cause:**
The bounds check on line 21 uses `if (index > buf->size)` instead of `if (index >= buf->size)`. This allows writing to the index that equals the buffer size, which is one byte past the end of the allocated buffer.

For a buffer allocated with size N:
- Valid indices: 0 to N-1
- Invalid index: N (and above)
- The buggy check only rejects indices > N, allowing index == N

**Crash Site:**
The actual out-of-bounds write occurs at line 24 where `buf->buf[index] = byte` is executed with an invalid index value.

**Impact:**
- Heap corruption: Writing one byte past the allocated buffer
- Can corrupt heap metadata or adjacent allocations
- Detected by AddressSanitizer as a heap-buffer-overflow

**Trigger Mechanism:**
The vulnerability is triggered through the longjmp-harness when specific arithmetic constraints are met:
- `input->a * input->b == 0x1337 * 0x1338` (25,589,448)
- `input->a + input->b == 0x1337 + 0x1338` (9,999)
- `input->c == 300` (the buffer size, causing off-by-one write)

## POV Analysis

The POV file (`pov_0.blob`) contains the input: `7  8  ,  ` (12 bytes).

This corresponds to an `InputFormat` structure:
```c
typedef struct InputFormat_s {
    int a;  // bytes 0-3
    int b;  // bytes 4-7
    int c;  // bytes 8-11
} InputFormat;
```

The POV provides values for `a`, `b`, and `c` that satisfy:
1. The arithmetic constraints to reach the vulnerable code path
2. `c = 300`, which triggers the off-by-one error when passed to `buffer_write()`

## Patch Analysis

The patch fixes the off-by-one error by correcting the bounds check:

```diff
-    if (index > buf->size) {
+    if (index >= buf->size) {
```

**Fix explanation:**
- Changes the comparison from `>` (greater than) to `>=` (greater than or equal)
- Now correctly rejects `index == buf->size`, which would be out of bounds
- Ensures only valid indices (0 to buf->size-1) can perform writes

This is a minimal, correct fix that addresses the root cause directly.

## Recommendations

- **Suggested CWEs**: [CWE-193, CWE-787, CWE-122]
- **Primary CWE**: CWE-193 (Off-by-one Error) - this best describes the root cause
- **Secondary CWEs**: CWE-787 (Out-of-bounds Write), CWE-122 (Heap-based Buffer Overflow)
- **Vulnerability Name**: "Off-by-one heap buffer overflow in buffer_write"
- **Severity**: Medium to High (heap corruption can lead to various security impacts)

**Additional Notes:**
- This is a synthetic vulnerability created for testing purposes (stress test benchmark)
- The vulnerability requires specific arithmetic constraints to be triggered
- The buffer_read() function (line 28-32) has the correct bounds check using `>=`, showing inconsistency in the original code