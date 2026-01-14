# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: pcre2_fuzzer
- **Vulnerability Type**: Heap-buffer-overflow (WRITE)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None found (no confirmed CVE or public advisory)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 4
- **Crash Location**: src/pcre2_compile.c:9278:9
- **Vulnerable Function**: get_grouplength
- **DEDUP Token**: get_grouplength--get_branchlength--get_grouplength
- **Scariness Score**: 36 (4-byte-write-heap-buffer-overflow)

### Stack Trace
The crash occurs during lookbehind pattern compilation with a recursive call pattern between `get_grouplength` and `get_branchlength`:

```
#0 get_grouplength /src/pcre2/src/pcre2_compile.c:9278:9
#1 get_branchlength /src/pcre2/src/pcre2_compile.c:9628:19
#2 get_grouplength /src/pcre2/src/pcre2_compile.c:9266:18
... (recursive pattern continues)
#18 set_lookbehind_lengths /src/pcre2/src/pcre2_compile.c:9758:18
#19 check_lookbehinds /src/pcre2/src/pcre2_compile.c:9958:10
#20 pcre2_compile_8 /src/pcre2/src/pcre2_compile.c:10414:15
#21 LLVMFuzzerTestOneInput /src/pcre2/src/pcre2_fuzzsupport.c:144:10
```

The buffer was allocated at:
```
#1 pcre2_compile_8 /src/pcre2/src/pcre2_compile.c:10404:20
```

### Memory Details
- **Out-of-bounds write address**: 0x519000000484
- **Allocated region**: [0x519000000080, 0x519000000484) - 1028 bytes
- **Write location**: 0 bytes **after** the allocated region (4-byte write beyond boundary)

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/pcre2_compile.c
- **Function**: get_grouplength
- **Line Range**: 9277-9278
- **Column Range**: 3-22

### Location 2 (root_cause)
- **Type**: root_cause  
- **File Path**: src/pcre2_compile.c
- **Function**: pcre2_compile_8
- **Line Range**: 10404-10405
- **Column Range**: 5-70

### Code Context

**Crash Site** (src/pcre2_compile.c:9277-9278):
```c
if (group > 0)
  {
  gi[0] |= (uint32_t)(GI_SET_FIXED_LENGTH | grouplength);  // Line 9277
  gi[1] = groupminlength;                                   // Line 9278 - CRASH HERE
  }
```

The crash occurs when writing to `gi[1]`, where `gi` is calculated as:
```c
uint32_t *gi = cb->groupinfo + 2 * group;  // Line 9240
```

**Root Cause** (src/pcre2_compile.c:10404-10405) - **VULNERABLE CODE**:
```c
cb.groupinfo = ccontext->memctl.malloc(
  (2 * cb.bracount + 1)*sizeof(uint32_t), ccontext->memctl.memory_data);
```

**Fixed Code** (from patch):
```c
cb.groupinfo = ccontext->memctl.malloc(
  (2 * (cb.bracount + 1))*sizeof(uint32_t), ccontext->memctl.memory_data);
```

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-131**: Incorrect Calculation of Buffer Size

## Vulnerability Description

This is a heap-based buffer overflow vulnerability in PCRE2's regular expression compiler when processing lookbehind assertions with nested groups. The vulnerability arises from an off-by-one error in the buffer size calculation for the `groupinfo` array.

**Root Cause:**
The code allocates a buffer sized for `(2 * cb.bracount + 1)` uint32_t elements. However, when the code accesses the groupinfo array using `gi = cb->groupinfo + 2 * group`, it can access beyond the allocated boundary when `group == cb.bracount`.

**Detailed Analysis:**
1. When `cb.bracount = N`, the allocation provides space for `2*N + 1` elements (indices 0 through 2*N)
2. Each group uses 2 elements: `gi[0]` and `gi[1]`
3. For group `N`, the code accesses:
   - `gi[0]` = `cb.groupinfo[2*N]` ✓ (valid - last allocated index)
   - `gi[1]` = `cb.groupinfo[2*N + 1]` ✗ (out of bounds!)
4. The write to `gi[1]` (line 9278) causes a 4-byte write past the end of the allocated 1028-byte buffer

**The Fix:**
The patch changes the allocation from `(2 * cb.bracount + 1)` to `(2 * (cb.bracount + 1))`, which provides `2*N + 2` elements, ensuring space for all groups including group N:
- Group N can now safely access indices `2*N` and `2*N + 1`

**Impact:**
- Heap corruption leading to potential arbitrary code execution
- Denial of service through crashes
- Triggered by specially crafted regular expressions with nested groups in lookbehind assertions

## POV Analysis

The POV file (`pov_0.blob`) is a 261-byte fuzzer-generated input that triggers this vulnerability. The input is designed to create a regex pattern with:
- Lookbehind assertions (`has_lookbehind` flag set to true)
- Multiple nested capturing groups with alternations (META_ALT)
- Group count equal to or near the allocation boundary
- Recursive pattern causing multiple calls between `get_grouplength` and `get_branchlength`

The fuzzer successfully discovered this edge case where the group number reaches `cb.bracount`, causing the out-of-bounds write during the caching operation.

## Patch Analysis

The patch (patch_0.diff) fixes the off-by-one error in buffer allocation:

**Change Location**: src/pcre2_compile.c:10405

**Before (vulnerable)**:
```c
(2 * cb.bracount + 1)*sizeof(uint32_t)
```

**After (fixed)**:
```c
(2 * (cb.bracount + 1))*sizeof(uint32_t)
```

**Why This Works:**
- With `bracount = N`, there are groups numbered 0 through N (N+1 groups total)
- Each group needs 2 uint32_t elements for caching
- Total elements needed: `2 * (N + 1) = 2*N + 2`
- The fix correctly allocates space for all groups including the highest-numbered group

The patch is a minimal, surgical fix that addresses the exact buffer size calculation error without changing the algorithm or data structures.

## Origin Classification Rationale

After comprehensive web searches for CVEs, GitHub issues, and PCRE2 advisories, I could not find any exact match for this specific vulnerability:
- No CVE references this specific `groupinfo` allocation bug
- No GitHub issues match the exact function and line numbers
- No PCRE2 release notes mention this specific fix
- The commit c13f2af8 appears to be a synthetic test case commit

While PCRE2 has had multiple heap-buffer-overflow vulnerabilities (CVE-2022-41409, CVE-2022-1587, various GitHub issues #77, #232, #275, #725), none match this specific vulnerability in the `get_grouplength` function at line 9278 with the `groupinfo` allocation issue at line 10405.

**Classification**: **synthetic** - This appears to be a synthetic vulnerability created for benchmark purposes, not a confirmed real-world 1-day vulnerability.

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-787, CWE-131]
- **Vulnerability Name**: "PCRE2 Lookbehind Group Info Buffer Overflow"
- **Severity**: High (heap corruption with potential for arbitrary code execution)
- **Attack Vector**: Malicious regex patterns with nested capturing groups in lookbehind assertions