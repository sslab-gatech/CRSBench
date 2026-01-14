# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: pov_harness
- **Vulnerability Type**: Heap Buffer Overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: src/core/ngx_string.c:1330
- **Vulnerable Function**: ngx_decode_base64_internal
- **DEDUP Token**: ngx_decode_base64_internal--ngx_http_userid_get_uid--ngx_http_userid_filter

### Stack Trace
The crash occurs during base64 decoding of a user ID cookie:
```
#0 ngx_decode_base64_internal /src/nginx/src/core/ngx_string.c:1330:14
#1 ngx_http_userid_get_uid /src/nginx/src/http/modules/ngx_http_userid_filter_module.c:361:9
#2 ngx_http_userid_filter /src/nginx/src/http/modules/ngx_http_userid_filter_module.c:242:11
```

The crash log shows:
- A **WRITE of size 1** at address 0x506000005c98
- The address is **0 bytes after a 56-byte region** [0x506000005c60,0x506000005c98)
- The buffer was allocated in `ngx_http_userid_get_uid` at line 333
- The overflow occurs during base64 decoding at line 1330 in `ngx_string.c`

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/core/ngx_string.c
- **Function**: ngx_decode_base64_internal
- **Line Range**: 1330-1330
- **Column Range**: 14-14

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/modules/ngx_http_userid_filter_module.c
- **Function**: ngx_http_userid_get_uid
- **Line Range**: 357-357
- **Column Range**: 5-5

### Code Context

**Crash Site** (src/core/ngx_string.c:1327-1334):
```c
while (len > 3) {
    *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);  // Line 1330 - CRASH HERE

    s += 4;
    len -= 4;
}
```

**Root Cause** (src/http/modules/ngx_http_userid_filter_module.c:350-361):
```c
if (ctx->cookie.len < 22) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent too short userid cookie \"%V\"",
                  &cookie->value);
    return ctx;
}

src = ctx->cookie;  // Line 357 - ROOT CAUSE: No length limit applied

dst.data = (u_char *) ctx->uid_got;

if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
```

The root cause is that while there's a check for minimum length (< 22), there's no check for maximum length, and the source string is passed directly to `ngx_decode_base64` without any length constraint.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-120**: Buffer Copy without Checking Size of Input

## Vulnerability Description

This is a **heap buffer overflow vulnerability** in nginx's userid filter module. The vulnerability occurs when processing maliciously crafted `uid` cookies in HTTP requests.

**Root Cause:**
In `ngx_http_userid_get_uid()`, the code checks if the cookie is too short (< 22 bytes) but does not enforce a maximum length. The cookie value is copied directly to `src` and passed to `ngx_decode_base64()` without constraining its length. The destination buffer `ctx->uid_got` is a fixed-size array (16 bytes for 4 uint32_t values), which can hold at most 16 bytes of decoded data (22 bytes of base64-encoded data).

**Exploitation:**
When a cookie value longer than 22 bytes is provided, the base64 decoding function writes beyond the allocated 56-byte buffer (which includes the `ngx_http_userid_ctx_t` structure), resulting in a heap buffer overflow.

**Impact:**
- Heap memory corruption
- Potential for arbitrary code execution
- Denial of service

## POV Analysis

The POV file contains an HTTP request with a maliciously crafted cookie:
```
GET / HTTP/1.1
Host: localhost
Cookie: uid=YWFhYWFhYWFhYWFhYWFhYWJiYmJiYmJiYmJiYmJiYmJjY2NjY2NjY2NjY2NjY2Njaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
```

The cookie value is approximately 134 characters of base64 data, far exceeding the expected 22 characters. When decoded, this produces enough data to overflow the fixed-size destination buffer.

## Patch Analysis

The patch adds a length constraint before base64 decoding:

```diff
@@ -355,6 +355,8 @@ ngx_http_userid_get_uid(...)
     }
 
     src = ctx->cookie;
+    
+    src.len = 22;  // FIX: Limit source length to expected size
 
     dst.data = (u_char *) ctx->uid_got;
```

**Fix Analysis:**
The patch limits `src.len` to exactly 22 bytes before passing it to `ngx_decode_base64()`. This ensures that:
1. The decoded output will be at most 16 bytes (22 * 3/4 = 16.5, rounded down)
2. The fixed-size destination buffer `ctx->uid_got` (16 bytes) will not overflow
3. Any excess cookie data beyond 22 bytes is ignored

This is a **maximum length enforcement** fix that prevents the buffer overflow by constraining the input size to match the expected/safe size for the destination buffer.

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-787, CWE-120]
- **Vulnerability Name**: Heap Buffer Overflow in nginx userid Cookie Base64 Decoding
- **Classification**: synthetic (no public CVE found)
- **Severity**: High (heap overflow with potential for code execution)