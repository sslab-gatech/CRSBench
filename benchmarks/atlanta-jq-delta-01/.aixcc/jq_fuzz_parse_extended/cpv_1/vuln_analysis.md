# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: jq_fuzz_parse_extended
- **Vulnerability Type**: Heap-based buffer overflow
- **Origin**: 1-day
- **Release Date**: 12/13/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-50246
  - https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 1 byte
- **Crash Location**: src/decNumber/decNumber.c:3764
- **Vulnerable Function**: decToString
- **DEDUP Token**: decToString--decNumberToString--jvp_literal_number_literal
- **Scariness Score**: 31 (1-byte-write-heap-buffer-overflow)

### Stack Trace
The vulnerability triggers through the following call chain:
```
#0 decToString /src/jq/src/decNumber/decNumber.c:3764:5
#1 decNumberToString /src/jq/src/decNumber/decNumber.c:449:3
#2 jvp_literal_number_literal /src/jq/src/jv.c:644:5
#3 jv_number_get_literal /src/jq/src/jv.c:659:12
#4 jv_dump_term /src/jq/src/jv_print.c:231:35
#5 jv_dumpf /src/jq/src/jv_print.c:368:3
#6 jv_dump /src/jq/src/jv_print.c:372:3
#7 LLVMFuzzerTestOneInput /src/jq/tests/jq_fuzz_parse_extended.c:27:5
```

### Memory Details
- **Overflow Address**: 0x5020000000c0
- **Allocated Buffer**: 16 bytes at region [0x5020000000b0, 0x5020000000c0)
- **Issue**: Writing null terminator 1 byte beyond allocated buffer boundary

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/jv.c
- **Function**: jvp_literal_number_literal
- **Line Range**: 638-639
- **Column Range**: 5-50

**Context**: The root cause is an incorrect buffer size calculation. The buffer is allocated without accounting for the null terminator:
```c
int len = jvp_dec_number_ptr(n)->digits + 14;
plit->literal_data = jv_mem_alloc(len);
```

According to the `decNumberToString` function documentation (line 444 of decNumber.c), the buffer "must be at least dn->digits+14 characters long", but this specification was ambiguous about the null terminator requirement.

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: src/decNumber/decNumber.c
- **Function**: decToString
- **Line Range**: 3764-3764
- **Column Range**: 3-14

**Context**: The crash occurs when writing the null terminator after converting the number to string:
```c
*c='\0';          // terminate the string (all paths)
```

This write goes 1 byte beyond the allocated buffer when the decimal number has the maximum number of digits and requires all 14 extra characters for formatting (sign, decimal point, exponent notation, etc.).

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow - Writing beyond the bounds of a heap-allocated buffer
- **CWE-787**: Out-of-bounds Write - Writing to a memory location outside of the intended buffer boundary
- **CWE-131**: Incorrect Calculation of Buffer Size - The buffer size calculation failed to account for the null terminator

## Vulnerability Description

An off-by-one heap buffer overflow vulnerability exists in jq's decimal number string conversion functionality. When converting decimal numbers to their string representation, the `jvp_literal_number_literal` function in `src/jv.c` allocates a buffer of size `digits + 14` bytes. However, this calculation does not account for the null terminator byte that `decNumberToString` writes at the end of the string.

The vulnerability manifests when processing decimal numbers with large exponents or many significant digits. The `decToString` function in `src/decNumber/decNumber.c` writes the null terminator at line 3764, which falls 1 byte beyond the allocated buffer boundary. This results in a heap buffer overflow that corrupts adjacent heap metadata or data structures.

**CVE-2023-50246** was discovered by the SEU-SSL research group, fixed by emanuele6, and patched in jq version 1.7.1 (released December 2023). The fix is a simple adjustment to the buffer size calculation:
```c
int len = jvp_dec_number_ptr(n)->digits + 15 /* 14 + NUL */;
```

This vulnerability can lead to:
- Application crashes (denial of service)
- Heap memory corruption
- Potentially arbitrary code execution if the overflow can be carefully controlled to corrupt critical data structures

## POV Analysis

The proof-of-vulnerability input is a specially crafted decimal number:
```
        -16E-1061947065
```

This input consists of:
- Leading whitespace (8 spaces)
- A negative sign
- The mantissa "16" (2 digits)
- Scientific notation with a very large negative exponent (-1061947065)

This particular combination triggers the maximum buffer requirement:
- The mantissa contributes 2 digits
- The sign, decimal point, 'E', and exponent sign require additional characters
- The large exponent requires many digits to represent
- The total approaches or reaches the `digits + 14` boundary, causing the null terminator to overflow

## Patch Analysis

The patch modifies `src/jv.c` line 638 to increase the buffer allocation by 1 byte:

**Before:**
```c
int len = jvp_dec_number_ptr(n)->digits + 14;
```

**After:**
```c
int len = jvp_dec_number_ptr(n)->digits + 15 /* 14 + NUL */;
```

The fix explicitly accounts for the null terminator byte, resolving the off-by-one error. The comment clarifies the intention: 14 bytes for the number formatting plus 1 byte for the NUL terminator.

This is the root cause location because:
1. The buffer is allocated here with insufficient size
2. The patch fixes the issue at this exact location
3. This is where the calculation error originated

The crash site (decNumber.c:3764) is simply where the overflow is manifested when the library function writes the null terminator to the undersized buffer provided by the caller.

## Recommendations

- **Suggested CWEs**: [CWE-122, CWE-787, CWE-131]
- **Vulnerability Name**: Heap buffer overflow in decimal number string conversion (off-by-one in jvp_literal_number_literal)
- **Origin Classification**: 1-day (CVE-2023-50246, confirmed exact match)
- **Severity**: High - Heap overflow with potential for exploitation
- **CVSS Score**: As documented in CVE-2023-50246