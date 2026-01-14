# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: pov_harness
- **Vulnerability Type**: AddressSanitizer: negative-size-param (integer underflow leading to negative size in memcpy)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (no CVE or security advisory found)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: negative-size-param
- **Crash Location**: src/http/modules/ngx_http_sub_filter_module.c:735
- **Vulnerable Function**: ngx_http_sub_parse
- **DEDUP Token**: `__asan_memcpy--ngx_http_sub_parse--ngx_http_sub_body_filter`

### Stack Trace
```
#0 __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
#1 ngx_http_sub_parse /src/nginx/src/http/modules/ngx_http_sub_filter_module.c:735:9
#2 ngx_http_sub_body_filter /src/nginx/src/http/modules/ngx_http_sub_filter_module.c:359:18
#3 ngx_http_addition_body_filter /src/nginx/src/http/modules/ngx_http_addition_filter_module.c:165:16
```

The crash occurs when `ngx_cpymem()` (which wraps `memcpy()`) is called with a negative size parameter (size=-1), triggering AddressSanitizer's detection.

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/http/modules/ngx_http_sub_filter_module.c
- **Function**: ngx_http_sub_parse
- **Line Range**: 735-735
- **Column Range**: 9-9

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/modules/ngx_http_sub_filter_module.c
- **Function**: ngx_http_sub_parse
- **Line Range**: 631-631
- **Column Range**: 18-18

### Code Context

**Root Cause (Line 631):**
```c
if (ctx->once) {
    /* sets start and next to end */
    offset = end + (ngx_int_t) tables->min_match_len;  // BUG: Should be -1
    goto again;
}
```

**Crash Site (Line 735):**
```c
len = ngx_max(next, 0);
p = ngx_cpymem(p, ctx->pos + len, end - len);  // CRASH: end - len becomes negative
```

## CWE Classification
- **CWE-191**: Integer Underflow (Wrap or Wraparound)
- **CWE-787**: Out-of-bounds Write
- **CWE-682**: Incorrect Calculation

## Vulnerability Description

This vulnerability is an **integer underflow** in nginx's HTTP substitution filter module (`ngx_http_sub_filter_module`). The bug occurs in the `ngx_http_sub_parse()` function when the `ctx->once` flag is set (indicating that substitution should only happen once).

**Root Cause:**
At line 631, when `ctx->once` is true, the code calculates an offset value:
```c
offset = end + (ngx_int_t) tables->min_match_len;
```

This offset is supposed to position the parser past the end of the buffer to prevent further matches. However, the calculation is off by one. The patch shows it should be:
```c
offset = end + (ngx_int_t) tables->min_match_len - 1;
```

**Impact Chain:**
1. The incorrect offset value propagates through the function flow
2. At line 714, `start` is recalculated: `start = offset - (ngx_int_t) tables->min_match_len + 1`
3. At line 730, `len = ngx_min(next, 0)` evaluates based on the incorrect values
4. At line 735, the expression `end - len` becomes negative because `end` and `len` are both derived from the incorrect offset calculation
5. This negative value is passed to `ngx_cpymem()` (a wrapper around `memcpy()`), which AddressSanitizer detects as a "negative-size-param" error

**Security Impact:**
While the immediate symptom is a negative size parameter causing a crash/denial of service, the underlying issue is an integer calculation error that could potentially lead to buffer overflows or memory corruption depending on how the negative value is interpreted by the system.

## POV Analysis
The POV file (`pov_0.blob`) is a 66-byte test case that triggers this vulnerability. It likely contains an HTTP request with specific headers or body content that:
- Activates the sub_filter module
- Sets the `ctx->once` flag to true (likely through the "sub_filter_once on" directive)
- Provides input that causes the min_match_len calculation to result in the integer underflow

## Patch Analysis

The patch file `patch_0.diff` shows a one-character fix:

```diff
-        offset = end + (ngx_int_t) tables->min_match_len;
+        offset = end + (ngx_int_t) tables->min_match_len - 1;
```

**Analysis:**
- The fix subtracts 1 from the offset calculation
- This corrects an off-by-one error in the boundary calculation
- The patch directly addresses the root cause at line 631
- By fixing the offset calculation when `ctx->once` is true, it prevents the downstream integer underflow that causes the negative size parameter at line 735

The patch location confirms that line 631 is the **root_cause** while line 735 (where the crash occurs with `ngx_cpymem`) is the **crash_site**.

## Origin Analysis

After extensive searching:
1. **Checked nginx security advisories**: No CVE found for ngx_http_sub_filter_module with negative-size-param
2. **Searched for CVEs**: No matching vulnerability found
3. **Web search**: Found various nginx CVEs but none matching this specific issue
4. **Conclusion**: This is a **synthetic** vulnerability created for testing purposes

## Recommendations
- **Suggested CWEs**: [CWE-191, CWE-787, CWE-682]
- **Vulnerability Name**: "Integer Underflow in nginx HTTP Sub Filter Module Once Mode"
- **Suggested Fix**: Apply the patch that corrects the offset calculation by subtracting 1
- **Testing**: Verify with POV that the negative-size-param error no longer occurs after patch application