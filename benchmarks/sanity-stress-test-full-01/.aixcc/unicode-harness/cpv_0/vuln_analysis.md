# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: unicode-harness
- **Vulnerability Type**: Heap-based Buffer Overflow (Off-by-one Error)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability for stress testing)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: utils.c:24:21
- **Vulnerable Function**: buffer_write
- **DEDUP Token**: buffer_write--func_unicode_破壊--LLVMFuzzerTestOneInput

### Stack Trace
```
#0 0x5598820c3a4d in buffer_write /src/cp-user-stress-test-src/utils.c:24:21
#1 0x5598820c376c in func_unicode_破壊 /src/cp-user-stress-test-src/unicode-harness.c:47:9
#2 0x5598820c385f in LLVMFuzzerTestOneInput /src/cp-user-stress-test-src/unicode-harness.c:57:5
```

### Memory Details
- **Operation**: WRITE of size 1 at address 0x5120000005ec
- **Buffer**: 300-byte region [0x5120000004c0, 0x5120000005ec)
- **Overflow Location**: 0 bytes after the 300-byte buffer (attempting to write at index 300)
- **Allocation Site**: buffer_create at utils.c:10

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 20-25
- **Column Range**: 5-26 (line 21)

The root cause is an off-by-one error in the bounds check at line 21. The condition `if (index > buf->size)` allows `index == buf->size`, which writes one byte past the end of the buffer.

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: utils.c
- **Function**: buffer_write
- **Line Range**: 24-24
- **Column Range**: 5-26

The crash occurs at line 24 where the out-of-bounds write is executed: `buf->buf[index] = byte;`

### Code Context

**Vulnerable code (utils.c:20-25):**
```c
void buffer_write(buffer_t *buf, size_t index, char byte) {
    if (index > buf->size) {  // ❌ OFF-BY-ONE: Should be >=
        return;
    }
    buf->buf[index] = byte;   // 💥 CRASH: Writes past buffer end when index == size
}
```

**Caller context (unicode-harness.c:25, 47):**
```c
buffer_t *buf = buffer_create(300);  // Allocates 300-byte buffer (indices 0-299)
// ...
buffer_write(buf, input->μεταβλητή_c, 'a');  // Writes at index 300 → overflow!
```

## CWE Classification
- **CWE-193**: Off-by-one Error - The primary defect; incorrect boundary condition allows access one element past the end
- **CWE-122**: Heap-based Buffer Overflow - The vulnerability class; heap buffer is written beyond its bounds
- **CWE-787**: Out-of-bounds Write - The general category; memory write operation outside valid buffer range

## Vulnerability Description

This is a **classic off-by-one error** in a bounds checking function. The `buffer_write` function is designed to prevent out-of-bounds writes by validating the index parameter. However, the bounds check uses the wrong comparison operator.

**The Defect:**
- Line 21 checks `if (index > buf->size)` instead of `if (index >= buf->size)`
- For a buffer of size N, valid indices are 0 to N-1
- The current check allows `index == buf->size`, which is out of bounds

**The Vulnerability Flow:**
1. A 300-byte buffer is allocated via `buffer_create(300)` at unicode-harness.c:25
2. Valid indices for this buffer are 0-299
3. The POV provides `μεταβλητή_c = 300` through the InputFormat structure
4. `buffer_write(buf, 300, 'a')` is called at unicode-harness.c:47
5. The bounds check `if (300 > 300)` evaluates to false, so execution continues
6. Line 24 executes `buf->buf[300] = 'a'`, writing 1 byte past the buffer end
7. AddressSanitizer detects the heap-buffer-overflow and aborts

**Impact:**
- Heap corruption: Writing past the buffer can corrupt adjacent heap metadata or data
- Potential for exploitation if the overwritten byte can be controlled
- Can lead to crashes, undefined behavior, or security vulnerabilities

## POV Analysis

The POV file (`pov_0.blob`) is a carefully crafted 12-byte input that maps to the `InputFormat` structure:

**Hex dump:**
```
00000000  37 13 00 00 38 13 00 00  2c 01 00 00
```

**Decoded structure:**
```c
InputFormat {
    変数a = 0x1337,         // 4919 decimal
    переменная_b = 0x1338,  // 4920 decimal
    μεταβλητή_c = 0x012c    // 300 decimal
}
```

**Why these values?**
1. The condition at unicode-harness.c:34 requires:
   - `変数a * переменная_b == 0x1337 * 0x1338` ✓
   - `変数a + переменная_b == 0x1337 + 0x1338` ✓
2. These values satisfy both conditions, triggering the vulnerable code path
3. `μεταβλητή_c = 300` is passed to `buffer_write` as the index
4. Since the buffer size is 300, index 300 is exactly one past the end (off-by-one)

The POV demonstrates precise control over the vulnerability, targeting the exact boundary condition that the bug allows.

## Patch Analysis

**Patch file:** patch_0.diff

The fix is a one-character change that corrects the bounds checking logic:

```diff
 void buffer_write(buffer_t *buf, size_t index, char byte) {
-    if (index > buf->size) {
+    if (index >= buf->size) {
         return;
     }
     buf->buf[index] = byte;
```

**What changed:**
- Changed comparison operator from `>` to `>=`
- Now correctly rejects `index == buf->size`
- Prevents the off-by-one write condition

**Why it works:**
- For a buffer of size N, valid indices are 0 to N-1
- The condition `index >= N` correctly identifies all out-of-bounds indices
- The function now returns early before the write can occur

**Note:** The `buffer_read` function at utils.c:27-32 already has the correct bounds check (`if (index >= buf->size)`), showing inconsistent implementation that likely contributed to the bug.

## Recommendations
- **Suggested CWEs**: [CWE-193, CWE-122, CWE-787]
- **Vulnerability Name**: Off-by-one heap buffer overflow in buffer_write function
- **Classification**: synthetic vulnerability (stress test)
- **Severity**: High (heap corruption, potential exploitation)

---## Analysis Complete ✅

I've completed a comprehensive vulnerability analysis for **cpv_0** in the **unicode-harness**. Here are the key findings:

### Vulnerability Summary
- **Type**: Off-by-one heap buffer overflow
- **Origin**: Synthetic (stress test vulnerability)
- **Severity**: High

### Root Cause
The vulnerability is a classic off-by-one error in `utils.c:21`:
- **Defect**: Uses `if (index > buf->size)` instead of `if (index >= buf->size)`
- **Impact**: Allows writing at `index == size`, which is one byte past the buffer end
- **Location**: `buffer_write` function at utils.c:20-25

### Attack Vector
The POV crafts input values that:
1. Satisfy the condition check to reach the vulnerable code path
2. Pass `index = 300` to a 300-byte buffer (valid indices: 0-299)
3. Trigger a heap-buffer-overflow write at the boundary

### Fix
The patch corrects the comparison operator from `>` to `>=`, properly rejecting out-of-bounds indices.

### CWE Classifications
- **CWE-193**: Off-by-one Error (primary)
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write

The detailed analysis above provides all the information needed for generating the `vuln.yaml` file, including precise code locations, stack traces, POV analysis, and patch details.