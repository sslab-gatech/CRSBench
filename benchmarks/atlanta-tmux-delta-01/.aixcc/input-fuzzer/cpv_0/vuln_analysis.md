# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: input-fuzzer
- **Vulnerability Type**: Stack buffer overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: stack-buffer-overflow
- **Crash Location**: input.c:2716
- **Vulnerable Function**: input_osc_52
- **DEDUP Token**: ___interceptor_strchr--input_osc_52--input_set_state

### Stack Trace
```
#0 0x55ded041e275 in strchr /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:712:5
#1 0x55ded05a2d98 in input_osc_52 /src/tmux/input.c:2716:38
#2 0x55ded0596192 in input_set_state /src/tmux/input.c:883:3
#3 0x55ded0596192 in input_parse /src/tmux/input.c:940:4
#4 0x55ded0595c8b in input_parse_buffer /src/tmux/input.c:982:2
```

The crash occurs at line 2716 where `strchr(flags, p[i])` is called. The `flags` buffer is declared at line 2697 with insufficient size, causing a READ of size 9 at offset 168 which overflows the `flags` variable (declared as 8 bytes at stack offset 160-168).

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: input.c
- **Function**: input_osc_52
- **Line Range**: 2697-2697
- **Column Range**: 1-45

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: input.c
- **Function**: input_osc_52
- **Line Range**: 2716-2716
- **Column Range**: 38-69

### Code Context

**Root Cause (Line 2697):**
```c
const char* allow = "cpqs01234567";
char flags[sizeof allow] = "";  // BUG: sizeof allow = 8 (pointer size)
u_int i, j = 0;
```

The bug is on line 2697 where `flags` is declared as `char flags[sizeof allow] = ""`. Since `allow` is a pointer, `sizeof allow` evaluates to 8 bytes (the size of a pointer on x86_64), not 13 bytes (the length of the string "cpqs01234567" plus null terminator).

**Crash Site (Lines 2713-2716):**
```c
for (i = 0; p + i != end; i++) {
    if (strchr(allow, p[i]) != NULL && strchr(flags, p[i]) == NULL)
        flags[j++] = p[i];  // Can write beyond 8-byte buffer
}
```

When more than 8 characters from the `allow` set are present in the input, the loop writes beyond the allocated 8 bytes, causing a stack buffer overflow.

## CWE Classification
- **CWE-121**: Stack-based Buffer Overflow
- **CWE-131**: Incorrect Calculation of Buffer Size
- **CWE-467**: Use of sizeof() on a Pointer Type

## Vulnerability Description

This is a classic stack buffer overflow vulnerability caused by incorrect use of the `sizeof` operator. The vulnerability was introduced in commit ccc9dc3bb49ac258c856d8478346b4ce829b188e (June 9, 2022) when implementing OSC 52 selection parameter validation for GitHub issue #3192.

**Root Cause:**
In the `input_osc_52` function, the `flags` buffer is declared as:
```c
const char* allow = "cpqs01234567";
char flags[sizeof allow] = "";
```

The developer intended to create a buffer large enough to hold all characters from the `allow` string. However, `sizeof allow` returns the size of the pointer (8 bytes on x86_64), not the size of the string literal. The correct declaration should be:
```c
char flags[sizeof "cpqs01234567"] = "";
```

This would allocate 13 bytes (12 characters + 1 null terminator).

**Exploitation:**
The vulnerability can be triggered by sending an OSC 52 escape sequence with a selection parameter containing many unique characters from the allowed set. The loop at lines 2713-2716 validates input characters and appends them to the `flags` buffer without proper bounds checking, relying on the assumption that `flags` is large enough to hold all possible values from `allow`.

When the input contains more than 8 unique characters from the allowed set "cpqs01234567", the write at line 2715 (`flags[j++] = p[i]`) overflows the stack-allocated buffer.

**Impact:**
- Stack corruption
- Potential code execution (depending on what data is overwritten)
- Denial of service (crash)

## POV Analysis

The POV file contains: `]52;5160psc24; \033`

This is an OSC 52 escape sequence with the selection parameter "5160psc24":
- The sequence starts with `]52;` (OSC 52 command)
- The first parameter is "5160psc24" which contains 9 unique characters from the allowed set
- This exceeds the 8-byte `flags` buffer, triggering the overflow

Characters from allowed set in the POV: 5, 1, 6, 0, p, s, c, 2, 4 = 9 unique characters

This causes the `flags` buffer to overflow when all 9 characters are written sequentially.

## Patch Analysis

The patch in `patch_0.diff` fixes the vulnerability by changing line 2697:

**Before (vulnerable):**
```c
char flags[sizeof allow] = "";
```

**After (fixed):**
```c
char flags[sizeof "cpqs01234567"] = "";
```

This ensures the buffer is allocated with the correct size of 13 bytes (string literal size) instead of 8 bytes (pointer size). The fix directly addresses the root cause by using `sizeof` on the string literal instead of the pointer variable.

## Vulnerability Classification Rationale

**Origin: synthetic**
After thorough investigation:
1. The vulnerability was introduced in commit ccc9dc3b (June 9, 2022) implementing GitHub issue #3192
2. Issue #3192 was a feature request, not a security issue
3. No CVE, OSV, or GHSA advisory exists for this specific bug
4. The bug appears to be a synthetic test case created from the patch, not a real-world disclosed vulnerability
5. The commits in the repository show this is at the vulnerable state, with no upstream fix commit found

**Release Date: 02/01/2026**
Using the default date for synthetic vulnerabilities as specified in the analysis guidelines.

## Recommendations
- **Suggested CWEs**: [CWE-121, CWE-131, CWE-467]
- **Vulnerability Name**: Stack Buffer Overflow in tmux input_osc_52 Function Due to Incorrect sizeof Usage