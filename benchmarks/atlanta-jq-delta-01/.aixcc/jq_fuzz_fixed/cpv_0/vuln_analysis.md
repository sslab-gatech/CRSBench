# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: jq_fuzz_fixed
- **Vulnerability Type**: Stack-based buffer overflow (NaN with payload)
- **Origin**: 1-day
- **Release Date**: 03/28/2025
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2024-53427
  - https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22

## Crash Log Analysis
- **Error Type**: AddressSanitizer: stack-buffer-overflow
- **Crash Location**: src/decNumber/decNumber.c:3375:45
- **Vulnerable Function**: decNumberCopy (crash site), jvp_number_cmp (root cause location)
- **DEDUP Token**: decNumberCopy--decNaNs--decCompareOp

### Stack Trace
The vulnerability is triggered through the following call stack:
```
#0 decNumberCopy /src/jq/src/decNumber/decNumber.c:3375:45
#1 decNaNs /src/jq/src/decNumber/decNumber.c:7706:33
#2 decCompareOp /src/jq/src/decNumber/decNumber.c:6085:7
#3 decNumberCompare /src/jq/src/decNumber/decNumber.c:858:3
#4 jvp_number_cmp /src/jq/src/jv.c:748:5
#5 jvp_number_equal /src/jq/src/jv.c:773:10
#6 jv_equal /src/jq/src/jv.c:1917:11
#7 jvp_array_equal /src/jq/src/jv.c:885:10
#8 jv_equal /src/jq/src/jv.c:1920:11
#9 jv_group /src/jq/src/jv_aux.c:715:11
#10 f_group_by_impl /src/jq/src/builtin.c:818:12
#11 jq_next /src/jq/src/execute.c:917:21
```

The crash occurs during a WRITE of size 2 at address 0x7fce5274fd70. The ASan report indicates:
```
This frame has 1 object(s):
  [32, 48) 'res' (line 743) <== Memory access at offset 48 overflows this variable
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/decNumber/decNumber.c
- **Function**: decNumberCopy
- **Line Range**: 3375-3375
- **Column Range**: 45-45

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/jv.c
- **Function**: jvp_literal_number_new
- **Line Range**: 586-594
- **Column Range**: 1-3

### Code Context

**Crash Site (decNumber.c:3375):**
```c
// decNumberCopy function - line 3375
for (s=src->lsu+1; s<smsup; s++, d++) *d=*s;
```
This line writes to a destination buffer without checking if the destination has sufficient space to hold all Units from the source decNumber.

**Root Cause (jv.c:586-594):**
```c
static jv jvp_literal_number_new(const char * literal) {
  jvp_literal_number* n = jv_mem_alloc(sizeof(jvp_literal_number));
  n->refcnt = JV_REFCNT_INIT;
  n->literal_data = NULL;
  decContext *ctx = DEC_CONTEXT();
  decContextClearStatus(ctx, DEC_Conversion_syntax);
  decNumberFromString(&n->num_decimal, literal, ctx);
  n->num_double = NAN;

  if (ctx->status & DEC_Conversion_syntax) {
    jv_mem_free(n);
    return JV_INVALID;
  }

  jv r = {JVP_FLAGS_NUMBER_LITERAL, 0, 0, JV_NUMBER_SIZE_INIT, {&n->refcnt}};
  return r;
}
```

The function accepts NaN with payload (e.g., "NaN123" or "nan6000000005") without validation, creating a decNumber with more digits than can be safely handled by the stack-allocated result buffer in `jvp_number_cmp`.

**Root Cause Location (jv.c:743-746):**
```c
int jvp_number_cmp(jv a, jv b) {
  // ...
  if (JVP_HAS_FLAGS(a, JVP_FLAGS_NUMBER_LITERAL) && JVP_HAS_FLAGS(b, JVP_FLAGS_NUMBER_LITERAL)) {
    struct {
      decNumber number;
      decNumberUnit units[1];  // Only space for 2 Units total (DECNUMUNITS=1 + 1 extra)
    } res;
```

The `res` structure allocates only 16 bytes (48-32=16 in the frame), but when comparing NaN values with large payloads (10+ digits), the `decNumberCompare` operation requires more Units than allocated, causing overflow.

## CWE Classification
- **CWE-121**: Stack-based Buffer Overflow (primary)
- **CWE-787**: Out-of-bounds Write
- **CWE-843**: Access of Resource Using Incompatible Type ('Type Confusion') - NaN treated as numeric

## Vulnerability Description

This is a stack-based buffer overflow vulnerability (CVE-2024-53427) in jq versions 1.7 and 1.7.1, representing an incomplete fix for CVE-2023-50268. 

The vulnerability occurs when comparing NaN values with payloads containing 10 or more decimal digits. The jq JSON processor supports non-standard JSON extensions including NaN with payload (e.g., "NaN123", "nan6000000005"). When such values are parsed through `jvp_literal_number_new()`, they create decNumber structures with multiple digits stored in the payload.

During comparison operations in `jvp_number_cmp()`, a stack-allocated result buffer is created with space for only 2 decNumberUnits (16 bytes total). However, when `decNumberCompare()` processes NaN values with large payloads, it requires more Units to store intermediate results. The `decNumberCopy()` function then writes beyond the allocated stack buffer, causing a 2-byte out-of-bounds write.

The vulnerability can be triggered through operations like:
- Array grouping with `group_by` when arrays contain NaN with payload
- Comparison operations between NaN values with extended payloads
- Equality checks involving such values

**Impact**: The stack buffer overflow can lead to memory corruption, potential code execution, or denial of service.

## POV Analysis

The POV file (`pov_0.blob`) contains:
```
[6,nan6000000005]\ 7\ �
```

This triggers the vulnerability by:
1. Creating an array with a NaN value that has a large payload ("nan6000000005" - 10 digits of payload)
2. The fuzzer harness likely performs grouping or comparison operations on this array
3. When comparing the NaN value, the large payload causes the stack buffer overflow in `jvp_number_cmp`

## Patch Analysis

The patch makes several critical changes to fix the vulnerability:

### Change 1: Reject NaN with payload (lines 19-27)
```c
+  if (decNumberIsNaN(&n->num_decimal)) {
+    // Reject NaN with payload.
+    if (n->num_decimal.digits > 1 || *n->num_decimal.lsu != 0) {
+      jv_mem_free(n);
+      return JV_INVALID;
+    }
+    jv_mem_free(n);
+    return jv_number(NAN);
+  }
```
This is the primary fix. It validates NaN values during parsing in `jvp_literal_number_new()`:
- If the NaN has more than 1 digit, it's rejected (payload detected)
- If the single Unit is non-zero, it's a payload (rejected)
- Only plain NaN (no payload) is accepted and converted to standard IEEE 754 NaN

### Change 2: Remove size tracking macros (lines 9-11)
```c
-#define JV_NUMBER_SIZE_INIT      (0)
-#define JV_NUMBER_SIZE_CONVERTED (1)
```
These macros were used to track whether a literal number had been converted to double, but this mechanism was fragile and replaced with a more robust check.

### Change 3: Use NaN check instead of size flag (lines 38-41)
```c
-    if (j.size != JV_NUMBER_SIZE_CONVERTED) {
+    if (isnan(n->num_double)) {
       n->num_double = jvp_literal_number_to_double(j);
-      j.size = JV_NUMBER_SIZE_CONVERTED;
     }
```
The conversion tracking now uses `isnan()` to check if conversion is needed, which is more reliable.

### Change 4: Use isnan() for NaN detection (line 50)
```c
-  return n.u.number != n.u.number;
+  return isnan(n.u.number);
```
Replace the NaN self-inequality test with the standard `isnan()` function.

**Root Cause Fix**: The patch addresses the root cause by rejecting NaN with payload at the parsing stage in `jvp_literal_number_new()`, preventing the creation of decNumber structures with large digit counts that would later overflow the stack buffer in `jvp_number_cmp()`.

## Recommendations
- **Suggested CWEs**: [CWE-121, CWE-787, CWE-843]
- **Vulnerability Name**: "Stack Buffer Overflow via NaN with Payload in jq Number Comparison"
- **Severity**: High (CVSS 8.1)
- **Fix**: Upgrade to jq 1.8.0 or apply patch to reject NaN with payload during JSON parsing