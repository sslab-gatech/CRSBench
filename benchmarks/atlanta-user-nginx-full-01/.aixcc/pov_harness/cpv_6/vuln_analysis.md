# Vulnerability Analysis for cpv_6

## Summary
- **CPV ID**: cpv_6
- **Harness**: pov_harness
- **Vulnerability Type**: NULL pointer dereference
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: N/A (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: SEGV (NULL pointer dereference)
- **Crash Location**: src/http/ngx_http_parse.c:2171
- **Vulnerable Function**: `ngx_http_parse_chunked`
- **DEDUP Token**: `ngx_http_parse_chunked--ngx_http_discard_request_body_filter--ngx_http_discard_request_body`
- **Scariness Score**: 10 (null-deref)

### Stack Trace
```
#0 0x5563431923f2 in ngx_http_parse_chunked /src/nginx/src/http/ngx_http_parse.c:2171:18
#1 0x55634319f051 in ngx_http_discard_request_body_filter /src/nginx/src/http/ngx_http_request_body.c:870:18
#2 0x55634319eb0d in ngx_http_discard_request_body /src/nginx/src/http/ngx_http_request_body.c:672:14
#3 0x556343171c72 in ngx_http_special_response_handler /src/nginx/src/http/ngx_http_special_response.c:473:9
#4 0x55634317cf42 in ngx_http_finalize_request /src/nginx/src/http/ngx_http_request.c:2565:38
```

The crash occurs when `ngx_http_parse_chunked` attempts to access `ctx->state` at line 2171, but `ctx` (which is `rb->chunked`) is NULL.

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/http/ngx_http_parse.c
- **Function**: `ngx_http_parse_chunked`
- **Line Range**: 2171-2171
- **Column Range**: 18-18

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/ngx_http_request_body.c
- **Function**: `ngx_http_discard_request_body_filter`
- **Line Range**: 863-863
- **Column Range**: 1-1

### Code Context

**Crash Site (ngx_http_parse.c:2171):**
```c
ngx_int_t
ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx)
{
    u_char     *pos, ch, c;
    ngx_int_t   rc;
    enum {
        sw_chunk_start = 0,
        sw_chunk_size,
        // ... more states ...
    } state;

    state = ctx->state;  // <-- Line 2171: NULL pointer dereference here
    // ...
}
```

**Root Cause (ngx_http_request_body.c:863):**
```c
if (r->headers_in.chunked) {

    rb = r->request_body;

    if (rb == NULL) {

        rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
        if (rb == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->chunked = NULL;  // <-- Line 863: Root cause - never initialized

        r->request_body = rb;
    }

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, b, rb->chunked);  // <-- Line 870: NULL passed as ctx
        // ...
    }
}
```

**The Fix (from patch_0.diff):**
```c
rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
if (rb == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

-            rb->chunked = NULL;
+            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
+            if (rb->chunked == NULL) {
+                return NGX_HTTP_INTERNAL_SERVER_ERROR;
+            }

r->request_body = rb;
```

## CWE Classification
- **CWE-476**: NULL Pointer Dereference - The code dereferences a NULL pointer (`ctx->state`), leading to a segmentation fault.

## Vulnerability Description

This is a **NULL pointer dereference vulnerability** in nginx's HTTP request body discard filter when handling chunked transfer encoding.

**Root Cause:**
In `ngx_http_discard_request_body_filter()` (line 863 of `ngx_http_request_body.c`), when a new request body structure is allocated for handling chunked requests, the `rb->chunked` field is explicitly set to NULL instead of being properly initialized with allocated memory.

**Crash Mechanism:**
1. An HTTP POST request arrives with `Transfer-Encoding: chunked` header
2. The server needs to discard the request body (e.g., during error handling)
3. `ngx_http_discard_request_body_filter()` is called
4. If `r->request_body` is NULL, a new structure is allocated
5. However, `rb->chunked` is set to NULL (line 863)
6. The code then calls `ngx_http_parse_chunked(r, b, rb->chunked)` (line 870)
7. Inside `ngx_http_parse_chunked()`, the code attempts to access `ctx->state` (line 2171)
8. Since `ctx` (which is `rb->chunked`) is NULL, this causes a NULL pointer dereference
9. AddressSanitizer detects the SEGV and crashes the program

**Impact:**
- Denial of Service (DoS) - worker process crash
- Triggered by remote attackers sending specially crafted HTTP requests with chunked transfer encoding

**Fix:**
The patch properly allocates memory for `rb->chunked` using `ngx_pcalloc()` instead of setting it to NULL, ensuring the chunked parser has a valid context structure to work with.

## POV Analysis

The proof-of-vulnerability test case (`pov_0.blob`) demonstrates the triggering condition:

```http
POST /upload HTTP/1.1
Host: localhost
Content-Type: application/json
Transfer-Encoding: chunked

2F
{
  "key1": "value1",
  "key2": "value2"
}
0

```

This is a valid HTTP chunked request:
- Uses `Transfer-Encoding: chunked` header
- Contains a chunked body with size `0x2F` (47 bytes)
- Ends with a zero-size chunk

When nginx processes this request and needs to discard the body (likely due to an error condition or routing decision), it triggers the NULL pointer dereference path because `rb->chunked` was never initialized.

## Patch Analysis

The patch modifies `src/http/ngx_http_request_body.c` in the `ngx_http_discard_request_body_filter()` function:

**Before (vulnerable):**
```c
rb->chunked = NULL;
```

**After (fixed):**
```c
rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
if (rb->chunked == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
```

The fix ensures that `rb->chunked` points to a properly allocated and zero-initialized `ngx_http_chunked_t` structure before it's passed to `ngx_http_parse_chunked()`. This prevents the NULL pointer dereference that occurred when the parser tried to access the `state` field of the context structure.

## Recommendations
- **Suggested CWEs**: [CWE-476]
- **Vulnerability Name**: nginx chunked transfer encoding NULL pointer dereference in request body discard filter
- **Severity**: Medium to High (remote DoS)
- **Origin Classification**: synthetic (no matching CVE found)

---

## Classification Rationale

This vulnerability is classified as **synthetic** rather than 1-day because:

1. **No exact CVE match found**: While CVE-2013-2028 affects `ngx_http_parse_chunked`, it describes a completely different vulnerability (stack buffer overflow due to integer signedness error), not a NULL pointer dereference in the discard filter.

2. **Different vulnerability mechanism**: 
   - CVE-2013-2028: Buffer overflow from large chunk size
   - This CPV: NULL pointer dereference from uninitialized `rb->chunked`

3. **Different code location for root cause**:
   - CVE-2013-2028: Issue in `ngx_http_parse.c` with chunk size handling
   - This CPV: Issue in `ngx_http_request_body.c` with structure initialization

4. **No official reference found**: Web searches did not reveal any official CVE, OSV, GHSA, or nginx security advisory matching this specific NULL pointer dereference pattern in the discard request body filter.

Therefore, following the strict classification rules (only mark as 1-day if there's an EXACT match), this is classified as **synthetic**.