# Vulnerability Analysis for cpv_7

## Summary
- **CPV ID**: cpv_7
- **Harness**: pov_harness
- **Vulnerability Type**: NULL pointer dereference (SEGV)
- **Origin**: synthetic (based on nginx ticket #2079 bug fix, not a CVE)
- **Release Date**: 02/01/2026
- **References**: https://trac.nginx.org/nginx/ticket/2079

## Crash Log Analysis

### Key Information
- **Error Type**: AddressSanitizer: SEGV (NULL pointer dereference)
- **Crash Location**: src/http/ngx_http_parse.c:1277
- **Vulnerable Function**: `ngx_http_parse_complex_uri`
- **DEDUP Token**: `ngx_http_parse_complex_uri--ngx_http_process_request_uri--ngx_http_process_request_line`
- **Signal**: WRITE memory access to address 0x000000000000 (zero page)
- **Scariness Score**: 10 (null-deref)

### Stack Trace
```
#0 0x55e459db0a6d in ngx_http_parse_complex_uri /src/nginx/src/http/ngx_http_parse.c:1277:14
#1 0x55e459d9e3fd in ngx_http_process_request_uri /src/nginx/src/http/ngx_http_request.c:1268:13
#2 0x55e459da4aea in ngx_http_process_request_line /src/nginx/src/http/ngx_http_request.c:1136:17
#3 0x55e459d2b689 in ngx_event_process_posted /src/nginx/src/event/ngx_event_posted.c:34:9
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/http/ngx_http_parse.c
- **Function**: ngx_http_parse_complex_uri
- **Line Range**: 1277-1277
- **Column Range**: 14-14

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/ngx_http_request.c
- **Function**: ngx_http_process_request_uri
- **Line Range**: 1258-1264
- **Column Range**: 1-9

### Code Context

**Crash Site** (src/http/ngx_http_parse.c:1272-1278):
```c
u = r->uri.data;
r->uri_ext = NULL;
r->args_start = NULL;

if (r->empty_path_in_uri) {
    *u++ = '/';  // Line 1277: NULL pointer dereference here
}
```

**Root Cause** (src/http/ngx_http_request.c:1256-1268):
```c
if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

    if(!r->empty_path_in_uri){
        r->uri.data = ngx_pnalloc(r->pool, 128);  // Only allocates if NOT empty_path_in_uri
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
        // Calls function that dereferences r->uri.data
```

## CWE Classification
- **CWE-476**: NULL Pointer Dereference
- **CWE-665**: Improper Initialization

## Vulnerability Description

This vulnerability is a NULL pointer dereference that occurs when nginx processes HTTP requests with absolute-form URIs containing empty paths followed by query strings (e.g., `GET http://localhost? HTTP/1.1`).

### Root Cause
The bug exists in `ngx_http_process_request_uri()` function in `src/http/ngx_http_request.c`. When the `empty_path_in_uri` flag is set to true (indicating the URI has an empty path component), the code incorrectly skips memory allocation for `r->uri.data`:

```c
if(!r->empty_path_in_uri){
    r->uri.data = ngx_pnalloc(r->pool, 128);  // Allocation SKIPPED when empty_path_in_uri is true
    if (r->uri.data == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }
}
```

### Crash Site
Subsequently, when `ngx_http_parse_complex_uri()` is called, it attempts to write a '/' character to `r->uri.data` when `empty_path_in_uri` is true:

```c
u = r->uri.data;  // u is NULL here
if (r->empty_path_in_uri) {
    *u++ = '/';  // SEGV: Writing to NULL pointer
}
```

### Impact
- **Denial of Service**: Causes worker process crash via NULL pointer dereference
- **Service Disruption**: Affects nginx's ability to proxy requests to AWS-compatible services using AWS C++ SDK
- **RFC Non-Compliance**: Violates RFC 7230 and RFC 3986 which permit empty paths in absolute-form URIs

## POV Analysis

**POV File**: pov_0.blob (51 bytes)

**Content** (ASCII representation):
```
GET http://localhost? HTTP/1.1
Host: localhost

```

This POV demonstrates a minimally crafted HTTP request that triggers the vulnerability:
- **Request method**: GET
- **Request URI**: `http://localhost?` (absolute-form URI with empty path and empty query string)
- **Protocol**: HTTP/1.1
- **Headers**: Single Host header

The key triggering element is the `?` character after the hostname without any path component (not even a `/`). This sets the `empty_path_in_uri` flag to true, causing the allocation to be skipped while later code expects `r->uri.data` to be valid.

## Patch Analysis

The patch corrects the logic in `ngx_http_process_request_uri()` by:

1. **Fixing the allocation condition** - Inverts the logic to properly handle `empty_path_in_uri`:
```diff
-        if(!r->empty_path_in_uri){
-            r->uri.data = ngx_pnalloc(r->pool, 128);
+        if (r->empty_path_in_uri) {
+            r->uri.len++;  // Account for the '/' that will be prepended
+        }
+        
+        r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
```

2. **Key improvements**:
   - **Always allocates memory** regardless of `empty_path_in_uri` flag
   - **Adjusts allocation size** by incrementing `r->uri.len` when `empty_path_in_uri` is true to account for the '/' character that will be prepended
   - **Uses actual URI length** (`r->uri.len`) instead of fixed 128 bytes for more precise allocation

This fix ensures that `r->uri.data` is never NULL when `ngx_http_parse_complex_uri()` attempts to write to it.

## Origin Classification: Synthetic

While this vulnerability is based on a real nginx bug tracked in **ticket #2079** (reported November 5, 2020, fixed December 10, 2020), it is classified as **synthetic** for the following reasons:

1. **No CVE assigned**: The nginx project did not assign a CVE identifier to this issue
2. **Bug fix, not security advisory**: This was treated as a functional bug fix for RFC compliance rather than a security vulnerability
3. **Not in official security databases**: No entries found in NVD, OSV, or GitHub Security Advisories
4. **Priority: Minor**: The ticket was downgraded from "major" to "minor" priority
5. **Primary impact**: Functional (AWS SDK compatibility) rather than security-focused

The changeset **8989fbd2f89aadfc879798127e66f5a85044ed44** by Maxim Dounin fixed the issue, but it was released as part of normal nginx development, not as a security patch.

## Recommendations

### Suggested CWEs
- **Primary**: CWE-476 (NULL Pointer Dereference)
- **Secondary**: CWE-665 (Improper Initialization)

### Vulnerability Name
"NULL Pointer Dereference in nginx URI Processing for Empty Path Absolute-form URIs"

### Additional Notes
- This vulnerability demonstrates the importance of proper memory initialization before use
- The fix aligns nginx with RFC 7230 and RFC 3986 compliance for absolute-form request URIs
- The issue particularly affected AWS SDK compatibility where such URI formats are generated