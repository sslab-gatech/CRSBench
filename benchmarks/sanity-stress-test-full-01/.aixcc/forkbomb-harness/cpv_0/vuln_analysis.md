# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: forkbomb-harness
- **Vulnerability Type**: Heap buffer overflow (off-by-one error in bounds check)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: utils.c:24:21
- **Vulnerable Function**: buffer_write
- **DEDUP Token**: buffer_write--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
- **Operation**: WRITE of size 1 at address 0x5120000005ec
- **Buffer Details**: Writing 0 bytes after a 300-byte region allocated at [0x5120000004c0, 0x5120000005ec)

### Stack Trace
```
#0 0x56399f89783d in buffer_write /src/cp-user-stress-test-src/utils.c:24:21
#1 0x56399f89766f in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/forkbomb-harness.c:60:5
#2 0x56399f74e310 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
```

### Allocation Stack Trace
```
#0 0x56399f85a0df in malloc
#1 0x56399f897715 in buffer_create /src/cp-user-stress-test-src/utils.c:10:16
#2 0x56399f89748c in func_forkbomb /src/cp-user-stress-test-src/forkbomb-harness.c:21:21
#3 0x56399f89766f in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/forkbomb-harness.c:60:5
```

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: Both crash_site and root_cause
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 20-25
- **Column Range**: Line 21: 5-29 (the conditional check)

### Code Context
```c
void buffer_write(buffer_t *buf, size_t index, char byte) {
    if (index > buf->size) {  // Line 21 - BUG: Should be >= not >
        return;
    }
    buf->buf[index] = byte;    // Line 24 - CRASH: Where overflow occurs
}
```

**Vulnerable Pattern**: The bounds check at line 21 uses `>` instead of `>=`, allowing writes at index equal to `buf->size`. Since valid indices for a buffer of size N are [0, N-1], writing at index N causes a one-byte overflow.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-193**: Off-by-one Error

## Vulnerability Description

This is a classic **off-by-one heap buffer overflow** vulnerability in the `buffer_write` function in `utils.c`.

**Root Cause**: The bounds check uses the wrong comparison operator:
- **Buggy code**: `if (index > buf->size)` allows writing when `index == buf->size`
- **Fixed code**: `if (index >= buf->size)` correctly rejects writes at or beyond the buffer size

**Attack Scenario**:
1. A buffer of size 300 is allocated via `buffer_create(300)` in `func_forkbomb` (line 21)
2. The buffer's valid indices are [0, 299]
3. When `input->c` equals 300, the bounds check `(300 > 300)` evaluates to false
4. The function proceeds to write at `buf->buf[300]`, which is one byte past the allocated region
5. AddressSanitizer detects the heap buffer overflow

**Impact**: 
- Allows one-byte write past the end of a heap-allocated buffer
- Can corrupt heap metadata or adjacent heap objects
- Potential for exploitation depending on what follows the buffer in memory

## POV Analysis

The POV file (`pov_0.blob`) contains 12 bytes structured as an `InputFormat` struct:
```
InputFormat {
    int a;  // bytes 0-3
    int b;  // bytes 4-7
    int c;  // bytes 8-11
}
```

The POV triggers the vulnerability by:
1. Satisfying the arithmetic constraints: `a * b == 0x1337 * 0x1338` and `a + b == 0x1337 + 0x1338`
2. Setting `c` to 300 (the buffer size), which bypasses the faulty bounds check
3. Causing `buffer_write(buf, 300, 'a')` to write one byte past the 300-byte buffer

This demonstrates a **targeted** exploit that solves specific arithmetic constraints to reach the vulnerable code path, rather than triggering the resource-exhausting fork bomb in the else branch.

## Patch Analysis

The patch fixes the off-by-one error with a minimal one-character change:

```diff
-    if (index > buf->size) {
+    if (index >= buf->size) {
```

**Fix correctness**: 
- Changes the comparison from `>` to `>=`
- Now correctly rejects writes when `index >= buf->size`
- Valid indices [0, size-1] are allowed; index == size is rejected
- This is the standard pattern for bounds checking (matching the `buffer_read` function at line 28)

**Note**: The `buffer_read` function (lines 27-32) already uses the correct `>=` operator, making this an inconsistency in the codebase where write checking was implemented incorrectly.

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-787, CWE-193]
- **Vulnerability Name**: Off-by-one heap buffer overflow in buffer_write bounds check
- **Severity**: Medium to High (heap corruption potential)
- **Classification**: Synthetic vulnerability (stress test for CRS systems)