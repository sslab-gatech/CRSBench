# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: pov_harness
- **Vulnerability Type**: Heap buffer overflow (write)
- **Origin**: synthetic
- **Release Date**: N/A
- **References**: None (no public CVE/advisory found)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 1
- **Crash Location**: src/core/ngx_string.c:1330:14
- **Vulnerable Function**: `ngx_decode_base64_internal`
- **DEDUP Token**: `ngx_decode_base64_internal--ngx_http_auth_basic_user--ngx_http_variable_remote_user`
- **Buffer Details**: Write 0 bytes after 17-byte region [0x503000037ff0, 0x503000038001)

### Stack Trace
```
#0 0x560cdc9cd982 in ngx_decode_base64_internal /src/nginx/src/core/ngx_string.c:1330:14
#1 0x560cdca5d906 in ngx_http_auth_basic_user /src/nginx/src/http/ngx_http_core_module.c:1994:9
#2 0x560cdca99f31 in ngx_http_variable_remote_user /src/nginx/src/http/ngx_http_variables.c:1760:10
#3 0x560cdca94d78 in ngx_http_get_indexed_variable /src/nginx/src/http/ngx_http_variables.c:647:9
#4 0x560cdca8ae8e in ngx_http_log_variable_getlen /src/nginx/src/http/modules/ngx_http_log_module.c:956:13
#5 0x560cdca89aca in ngx_http_log_handler /src/nginx/src/http/modules/ngx_http_log_module.c:305:24
```

### Allocation Stack Trace
The 17-byte buffer was allocated at:
```
#0 0x560cdc97739f in malloc
#1 0x560cdca22994 in ngx_alloc /src/nginx/src/os/unix/ngx_alloc.c:22:9
#2 0x560cdc9bedea in ngx_palloc_large /src/nginx/src/core/ngx_palloc.c:220:9
#3 0x560cdca5d8ee in ngx_http_auth_basic_user /src/nginx/src/http/ngx_http_core_module.c:1989:17
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/core/ngx_string.c
- **Function**: ngx_decode_base64_internal
- **Line Range**: 1330-1330
- **Column Range**: 14-14

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/ngx_http_core_module.c
- **Function**: ngx_http_auth_basic_user
- **Line Range**: 1988-1989
- **Column Range**: 5-52

### Code Context

**Crash Site** (`src/core/ngx_string.c:1330`):
```c
while (len > 3) {
    *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);  // LINE 1330: Overflow occurs here

    s += 4;
    len -= 4;
}
```

**Root Cause** (`src/http/ngx_http_core_module.c:1988-1989`):
```c
auth.len = NGX_HTTP_AUTH_MAX;  // LINE 1988: Fixed constant of 16 bytes
auth.data = ngx_pnalloc(r->pool, auth.len + 1);  // LINE 1989: Allocates only 17 bytes total
if (auth.data == NULL) {
    return NGX_ERROR;
}

if (ngx_decode_base64(&auth, &encoded) != NGX_OK) {  // LINE 1994: Decodes into fixed buffer
    r->headers_in.user.data = (u_char *) "";
    return NGX_DECLINED;
}
```

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-131**: Incorrect Calculation of Buffer Size

## Vulnerability Description

The `ngx_http_auth_basic_user()` function in `src/http/ngx_http_core_module.c` allocates a fixed-size buffer of **16 bytes** (defined as `NGX_HTTP_AUTH_MAX`) plus 1 byte for null termination (total 17 bytes) to store decoded base64 credentials:

```c
auth.len = NGX_HTTP_AUTH_MAX;  // Fixed at 16 bytes
auth.data = ngx_pnalloc(r->pool, auth.len + 1);
```

The `NGX_HTTP_AUTH_MAX` constant is defined in `src/http/ngx_http_core_module.h` as:
```c
#define NGX_HTTP_AUTH_MAX               16
```

However, the actual size needed to store decoded base64 data depends on the length of the encoded input. When an attacker provides a base64-encoded authentication header longer than 24 characters (which decodes to more than 18 bytes, exceeding the 16-byte buffer plus null terminator), the `ngx_decode_base64_internal()` function writes beyond the allocated buffer boundary.

The vulnerability occurs at line 1330 in `src/core/ngx_string.c` during the base64 decoding loop:
```c
*d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);
```

This is a **heap-based buffer overflow** where the write operation exceeds the allocated 17-byte region.

### Impact
- Memory corruption on the heap
- Potential for arbitrary code execution if an attacker can control heap layout
- Denial of service through application crash
- Information disclosure through heap metadata corruption

## POV Analysis

The POV file (`pov_0.blob`) is a crafted HTTP request containing a base64-encoded Authorization header that exceeds the fixed buffer size. The base64-encoded string, when decoded, produces more than 16 bytes of output, triggering the heap buffer overflow.

## Patch Analysis

The patch fixes the vulnerability by replacing the fixed-size buffer allocation with a dynamically calculated size based on the actual encoded input length:

**Before (vulnerable)**:
```c
auth.len = NGX_HTTP_AUTH_MAX;
```

**After (fixed)**:
```c
auth.len = ngx_base64_decoded_length(encoded.len);
```

The `ngx_base64_decoded_length()` macro is defined in `src/core/ngx_string.h` as:
```c
#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)
```

This properly calculates the required buffer size based on the base64 encoding formula, ensuring the allocated buffer is always large enough to hold the decoded data, preventing the overflow.

### Root Cause vs Crash Site
- **Root Cause**: The bug exists at line 1988 in `src/http/ngx_http_core_module.c` where the fixed constant `NGX_HTTP_AUTH_MAX` is used instead of calculating the proper buffer size
- **Crash Site**: The overflow manifests at line 1330 in `src/core/ngx_string.c` where the base64 decoding writes beyond the undersized buffer

## Origin Classification

After searching nginx's official security advisories (https://nginx.org/en/security_advisories.html), CVE databases, and related vulnerability sources, **no public CVE or security advisory was found** that matches this specific vulnerability in the `ngx_http_auth_basic_user` function.

The search covered:
- Official nginx security advisories
- NVD (National Vulnerability Database)
- CVE Details
- OSV (Open Source Vulnerabilities)
- GitHub Security Advisories

While several nginx buffer overflow vulnerabilities exist (CVE-2012-2089, CVE-2014-0133, CVE-2013-2028), none match the specific function, file location, and fix pattern observed in this vulnerability.

**Conclusion**: This is a **synthetic** vulnerability - it does not correspond to a publicly disclosed 1-day vulnerability.

## Recommendations

### Suggested CWEs
- CWE-122 (Heap-based Buffer Overflow)
- CWE-787 (Out-of-bounds Write)
- CWE-131 (Incorrect Calculation of Buffer Size)

### Vulnerability Name
"Heap Buffer Overflow in nginx HTTP Basic Authentication Base64 Decoding"

### Severity
**High** - Heap buffer overflow vulnerabilities can lead to arbitrary code execution, making this a serious security issue that affects HTTP Basic Authentication handling.