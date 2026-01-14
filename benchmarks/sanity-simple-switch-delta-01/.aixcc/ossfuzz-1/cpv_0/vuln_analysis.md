# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ossfuzz-1
- **Vulnerability Type**: Stack buffer overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: stack-buffer-overflow
- **Crash Location**: simple.c (line 19, in `target` function based on context)
- **Vulnerable Function**: target
- **DEDUP Token**: target
- **Operation**: WRITE of size 71 at stack address

### Stack Trace
```
#0 0x558a41bb1033 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
#1 0x558a41bf2af7 in target /src/simple-switch/simple.c
#2 0x558a41bf278f in LLVMFuzzerTestOneInput /src/fuzz/ossfuzz-1.c:4:3
```

### Memory Layout Analysis
From the crash log, the stack frame shows:
- `buf1` [32, 48): 16 bytes (0x10)
- `buf2` [64, 96): 32 bytes (0x20) 
- Memory access at offset 48 partially underflows buf2

The crash indicates a 71-byte write starting at offset 48, which overflows buf1 (only 16 bytes) and corrupts adjacent stack memory.

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: crash_site, root_cause
- **File Path**: simple.c
- **Function**: target
- **Line Range**: 19-19
- **Column Range**: 5-38

### Code Context
```c
void target(const uint8_t *data, size_t size) {
  if (size < 1) {
    return;
  }
  uint8_t cmd = data[0];
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;
  char buf1[0x10] = {};      // Line 12: 16-byte buffer
  char buf2[0x20] = {};
  char buf3[0x30] = {};
  char buf4[0x40] = {};
  char buf5[0x50] = {};
  switch (cmd) {
  case 1:
    memcpy(buf1, payload, payload_size);  // Line 19: VULNERABLE - no bounds check
    break;
  case 2:
    if (payload_size < sizeof(buf2)) {    // Line 22: Cases 2-5 have proper checks
      memcpy(buf2, payload, payload_size);
    }
    break;
  // ... other cases with proper bounds checks ...
```

## CWE Classification
- **CWE-121**: Stack-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-120**: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

## Vulnerability Description

This is a classic **stack-based buffer overflow** vulnerability in the `target` function in `simple.c`.

**Root Cause**: 
The vulnerability exists at line 19 where `memcpy(buf1, payload, payload_size)` is called without any bounds checking. The function accepts arbitrary-sized input data and copies it directly into a fixed-size 16-byte stack buffer (`buf1`).

**Vulnerability Flow**:
1. User-controlled data arrives via the `data` parameter
2. The first byte is used as a command (`cmd = data[0]`)
3. Remaining data becomes payload (`payload = data + 1`, `payload_size = size - 1`)
4. When `cmd == 1`, the code performs `memcpy(buf1, payload, payload_size)` with NO size validation
5. If `payload_size > 16`, the memcpy overwrites adjacent stack memory

**Contrast with Safe Cases**:
Cases 2-5 all include proper bounds checking:
```c
if (payload_size < sizeof(buf2)) {
    memcpy(buf2, payload, payload_size);
}
```

Case 1 is missing this crucial check, making it exploitable.

**Impact**:
- Stack corruption leading to crashes
- Potential for arbitrary code execution if attacker can control overwritten return addresses
- Information disclosure through overwritten stack data

## POV Analysis

The POV file (`pov_0.blob`, 72 bytes) demonstrates the vulnerability:

**Structure**:
- Byte 0: `0x01` (command byte - selects case 1)
- Bytes 1-71: `0x61` ('a' character) repeated 71 times

**Attack**:
The POV sends 72 bytes total:
- 1 byte for command (0x01)
- 71 bytes of payload ('a' repeated)

Since `buf1` is only 16 bytes (0x10), the 71-byte memcpy causes a 55-byte overflow, corrupting adjacent stack memory including `buf2` and potentially beyond.

## Patch Analysis

The patch (patch_0.diff) fixes the vulnerability by adding the missing bounds check:

**Before (vulnerable)**:
```c
case 1:
    memcpy(buf1, payload, payload_size);
    break;
```

**After (fixed)**:
```c
case 1:
    if (payload_size < sizeof(buf1)) {
      memcpy(buf1, payload, payload_size);
    }
    break;
```

**Fix Explanation**:
- Adds size validation matching the pattern used in cases 2-5
- Only performs memcpy if payload_size is smaller than the buffer size
- Prevents overflow by rejecting oversized inputs

## Recommendations
- **Suggested CWEs**: [CWE-121, CWE-787, CWE-120]
- **Vulnerability Name**: Stack buffer overflow in target function case 1
- **Severity**: High - allows stack corruption with user-controlled data
- **Location Type**: Both crash_site and root_cause are at line 19 (the missing bounds check is the defect that causes the crash)