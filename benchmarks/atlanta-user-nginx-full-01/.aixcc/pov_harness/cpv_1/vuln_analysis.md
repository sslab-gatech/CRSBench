# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: pov_harness
- **Vulnerability Type**: Heap Buffer Overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (no matching CVE found)

## Crash Log Analysis

### Error Details
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: `src/http/ngx_http_parse.c:1298`
- **Vulnerable Function**: `ngx_http_parse_complex_uri`
- **Operation**: WRITE of size 1
- **DEDUP Token**: `ngx_http_parse_complex_uri--ngx_http_process_request_uri--ngx_http_process_request_line`

### Stack Trace
The crash occurs in the following call chain:
```
#0 ngx_http_parse_complex_uri /src/nginx/src/http/ngx_http_parse.c:1298:22
#1 ngx_http_process_request_uri /src/nginx/src/http/ngx_http_request.c:1268:13
#2 ngx_http_process_request_line /src/nginx/src/http/ngx_http_request.c:1136:17
#3 ngx_event_process_posted /src/nginx/src/event/ngx_event_posted.c:34:9
```

### Memory Details
- **Overflow Location**: `0x50c000001c80` (0 bytes after 128-byte region)
- **Allocated Region**: `[0x50c000001c00, 0x50c000001c80)` (128 bytes)
- **Allocation Call Stack**:
  ```
  #1 ngx_alloc /src/nginx/src/os/unix/ngx_alloc.c:22:9
  #2 ngx_palloc_large /src/nginx/src/core/ngx_palloc.c:220:9
  #3 ngx_http_process_request_uri /src/nginx/src/http/ngx_http_request.c:1259:27
  ```

## Vulnerable Code Location(s)

### Location 1: crash_site
- **Type**: crash_site
- **File Path**: `src/http/ngx_http_parse.c`
- **Function**: `ngx_http_parse_complex_uri`
- **Line Range**: 1298-1298
- **Column Range**: 22-22

### Location 2: root_cause
- **Type**: root_cause
- **File Path**: `src/http/ngx_http_request.c`
- **Function**: `ngx_http_process_request_uri`
- **Line Range**: 1259-1259
- **Column Range**: 1-1

### Code Context

**Root Cause (src/http/ngx_http_request.c:1259)**:
```c
if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

    if(!r->empty_path_in_uri){
        r->uri.data = ngx_pnalloc(r->pool, 128);  // BUG: Fixed-size allocation
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
        // ...
    }
```

**Crash Site (src/http/ngx_http_parse.c:1298)**:
```c
case sw_usual:

    if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
        *u++ = ch;  // CRASH: Writing past allocated buffer
        ch = *p++;
        break;
    }
```

## Patch Analysis

The patch modifies `src/http/ngx_http_request.c` at line 1259:

**Before (vulnerable)**:
```c
r->uri.data = ngx_pnalloc(r->pool, 128);
```

**After (fixed)**:
```c
r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
```

**Fix Description**: The vulnerability was caused by allocating a fixed 128-byte buffer for URI data, regardless of the actual URI length (`r->uri.len`). When a URI longer than 128 bytes is processed (especially with URL encoding like `%20` for spaces), the `ngx_http_parse_complex_uri` function writes past the allocated buffer boundary, causing a heap buffer overflow.

## POV Analysis

The POV file (`pov_0.blob`) contains an HTTP GET request with a long URI path:
```
GET /search%20with%20spacesaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/api%2Fv1?param1=value%201&param2=some%20encoded HTTP/1.1
```

**Key characteristics**:
- Contains URL-encoded characters (`%20` for space, `%2F` for slash)
- Has a very long path component with repeated 'a' characters
- Total URI length exceeds 128 bytes
- Triggers the `complex_uri` path (due to URL encoding) which allocates only 128 bytes
- During parsing in `ngx_http_parse_complex_uri`, the decoded URI data is written byte-by-byte, overflowing the fixed 128-byte buffer

## CWE Classification

- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-131**: Incorrect Calculation of Buffer Size (root cause)

## Vulnerability Description

A heap buffer overflow vulnerability exists in nginx's HTTP request processing code. When processing HTTP requests with complex URIs (containing URL-encoded characters), the `ngx_http_process_request_uri` function allocates a fixed 128-byte buffer for URI data, regardless of the actual URI length. 

The vulnerability occurs when:
1. An HTTP request contains a URI with URL-encoded characters (triggering `r->complex_uri`)
2. The URI length (`r->uri.len`) exceeds 128 bytes
3. A fixed 128-byte buffer is allocated via `ngx_pnalloc(r->pool, 128)`
4. The `ngx_http_parse_complex_uri` function decodes and writes the URI data byte-by-byte into this buffer
5. Writing continues past the 128-byte boundary, causing a heap buffer overflow

**Impact**: An unauthenticated remote attacker can send a specially crafted HTTP request with a long URI containing URL-encoded characters to trigger a heap buffer overflow, potentially leading to:
- Denial of Service (worker process crash)
- Memory corruption
- Potentially arbitrary code execution (depending on heap layout and exploit techniques)

## Recommendations

- **Suggested CWEs**: [CWE-122, CWE-787, CWE-131]
- **Vulnerability Name**: nginx HTTP Request URI Heap Buffer Overflow
- **Severity**: High (remote, unauthenticated, heap corruption)
- **Fix**: Change buffer allocation from fixed size (128 bytes) to dynamic size based on actual URI length (`r->uri.len`)