# Vulnerability Analysis for cpv_8

## Summary
- **CPV ID**: cpv_8
- **Harness**: pov_harness
- **Vulnerability Type**: Stack Buffer Overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: stack-buffer-overflow
- **Crash Location**: src/http/ngx_http_parse.c:765
- **Vulnerable Function**: ngx_http_parse_request_line
- **DEDUP Token**: `__interceptor_vsprintf--__interceptor_sprintf--ngx_http_parse_request_line`
- **Operation**: WRITE of size 4 at stack address
- **Scariness Score**: 51 (4-byte-write-stack-buffer-overflow)

### Stack Trace
```
#0 vsprintf - sanitizer interceptor
#1 sprintf - sanitizer interceptor  
#2 ngx_http_parse_request_line /src/nginx/src/http/ngx_http_parse.c:765:17 [CRASH SITE]
#3 ngx_http_process_request_line /src/nginx/src/http/ngx_http_request.c:1116:14
#4 ngx_event_process_posted /src/nginx/src/event/ngx_event_posted.c:34:9
#5 LLVMFuzzerTestOneInput (harness code)
```

### Memory Details
From AddressSanitizer output:
- **Buffer**: `minor_version_temp` at line 764, size 3 bytes (offset 32-35 in stack frame)
- **Overflow**: Write at offset 35 overflows the 3-byte buffer
- The buffer can hold at most 2 digit characters plus null terminator ("99\0")
- When `r->http_minor` has 4 digits (e.g., 1110), `sprintf` writes 5 bytes ("1110\0"), overflowing by 2 bytes

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: Both crash_site and root_cause
- **File Path**: src/http/ngx_http_parse.c
- **Function**: ngx_http_parse_request_line
- **Line Range**: 764-765
- **Column Range**: 17 (line 765)

### Code Context
```c
if (r->http_minor > 99) {
    char minor_version_temp[3] = {};        // Line 764: Only 3 bytes allocated
    sprintf(minor_version_temp, "%u", r->http_minor);  // Line 765: CRASH SITE - overflows when value > 999
    //ngx_record_wrong_minor_version(minor_version_temp);
    return NGX_HTTP_PARSE_INVALID_REQUEST;
}

r->http_minor = r->http_minor * 10 + (ch - '0');  // Line 770: accumulates digits
```

### Vulnerability Flow
1. **Input**: HTTP request line with minor version digits (e.g., "HTTP/1.1110")
2. **Parsing**: Each digit in minor version is processed in state `sw_minor_digit`
3. **Accumulation**: `r->http_minor = r->http_minor * 10 + (ch - '0')` accumulates value
4. **Check**: When `r->http_minor > 99`, code checks if value exceeds expected range
5. **Bug**: Allocates only 3-byte buffer but `sprintf` writes 4+ bytes for values ≥ 1000
6. **Crash**: Stack buffer overflow occurs at `sprintf` call (line 765)

## CWE Classification
- **CWE-121**: Stack-based Buffer Overflow - Writing to a stack buffer beyond its bounds
- **CWE-787**: Out-of-bounds Write - Memory write outside allocated buffer
- **CWE-120**: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

## Vulnerability Description

This is a **stack-based buffer overflow** vulnerability in the HTTP request line parser. The vulnerability occurs in the `ngx_http_parse_request_line` function when parsing the HTTP minor version number.

**Root Cause**: 
The code allocates a 3-byte stack buffer (`minor_version_temp[3]`) to store a string representation of the HTTP minor version number, but uses unsafe `sprintf` without bounds checking. The buffer can only safely hold 2-digit numbers ("99\0"), but the code can reach this point with values much larger than 99 (the check happens at line 763, but the multiplication at line 770 occurs after).

**Trigger Condition**:
When an HTTP request contains a minor version with 4 or more digits (e.g., "HTTP/1.1110"), the `r->http_minor` value becomes >= 1000. The subsequent `sprintf` call attempts to write "1110\0" (5 bytes) into the 3-byte buffer, causing a stack buffer overflow.

**Impact**:
- Memory corruption on the stack
- Potential for arbitrary code execution if attacker can control overwritten data
- Crash/DoS is guaranteed when overflow occurs

**Note**: This vulnerability appears to be synthetic (intentionally injected for testing). The code pattern (checking `r->http_minor > 99` but then allowing it to grow larger, plus the commented-out logging function) suggests this was added to create a controlled vulnerability scenario rather than being a real-world bug.

## POV Analysis

**POV File**: pov_0.blob
```
GET / HTTP/1.1110
Host: localhost
```

**Analysis**:
- The POV triggers the vulnerability by specifying HTTP version "1.1110"
- The minor version "1110" (4 digits) requires 5 bytes to store as string ("1110\0")
- This exceeds the 3-byte buffer capacity, triggering the overflow
- The POV is minimal and focused, demonstrating clear understanding of the vulnerability

## Patch Analysis

**Patch File**: patch_0.diff

The patch **removes** the vulnerable code entirely:
```diff
if (r->http_minor > 99) {
-    char minor_version_temp[3] = {};
-    sprintf(minor_version_temp, "%u", r->http_minor);
-    //ngx_record_wrong_minor_version(minor_version_temp);
     return NGX_HTTP_PARSE_INVALID_REQUEST;
}
```

**Fix Strategy**:
- Eliminates the stack buffer allocation and unsafe `sprintf` call
- Maintains the check for `r->http_minor > 99`
- Simply returns error without attempting to log the invalid value
- This is a complete fix that removes the vulnerability by eliminating the unsafe code path

**Why This Works**:
- No buffer allocation means no buffer overflow possible
- The validation logic (returning error for minor version > 99) remains intact
- Removes unnecessary logging code that was vulnerable

## Recommendations

### Classification
- **CWEs**: [CWE-121, CWE-787, CWE-120]
- **Vulnerability Name**: "Stack Buffer Overflow in HTTP Version Parsing"
- **Origin**: synthetic
- **Release Date**: 02/01/2026

### Location Details for vuln.yaml
- **crash_site**: src/http/ngx_http_parse.c, function `ngx_http_parse_request_line`, line 765, column 17
- **root_cause**: Same as crash_site (the vulnerable `sprintf` call is both where the bug exists and where it manifests)