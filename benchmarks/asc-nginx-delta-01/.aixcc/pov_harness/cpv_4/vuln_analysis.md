# Vulnerability Analysis for cpv_4

## Summary
- **CPV ID**: cpv_4
- **Harness**: pov_harness
- **Vulnerability Type**: Heap Buffer Overflow (Write)
- **Origin**: synthetic
- **Release Date**: N/A (synthetic vulnerability)
- **References**: None (synthetic vulnerability created for benchmark purposes)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: src/core/ngx_string.c:581:24
- **Vulnerable Function**: `ngx_sprintf_str`
- **Write Operation**: WRITE of size 1 at address 0x5040000024fb
- **DEDUP Token**: `ngx_sprintf_str--ngx_vslprintf--ngx_sprintf`
- **Buffer Details**: Write occurred 0 bytes after a 43-byte allocated region

### Stack Trace
```
#0 ngx_sprintf_str /src/nginx/src/core/ngx_string.c:581:24
#1 ngx_vslprintf /src/nginx/src/core/ngx_string.c
#2 ngx_sprintf /src/nginx/src/core/ngx_string.c:129:9
#3 ngx_http_set_browser_cookie /src/nginx/src/http/ngx_http_core_module.c:5289:37
#4 ngx_http_static_handler /src/nginx/src/http/modules/ngx_http_static_module.c:243:9
```

The allocation trace shows the buffer was allocated in `ngx_http_set_browser_cookie` at line 5281:
```
#3 ngx_palloc_large /src/nginx/src/core/ngx_palloc.c:220:9
#4 ngx_http_set_browser_cookie /src/nginx/src/http/ngx_http_core_module.c:5281:34
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/core/ngx_string.c
- **Function**: ngx_sprintf_str
- **Line Range**: 581-581
- **Column Range**: 24-24

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/http/ngx_http_core_module.c
- **Function**: ngx_http_set_browser_cookie
- **Line Range**: 5281-5281
- **Column Range**: 34-34

### Code Context

**Root Cause Location (src/http/ngx_http_core_module.c:5281)**:
```c
ngx_int_t
ngx_http_set_browser_cookie(ngx_http_request_t *r)
{
    ngx_table_elt_t           *browser_cookie;

    if (!r->headers_in.safari && !r->headers_in.msie && !r->headers_in.chrome) {
        return NGX_OK;
    }

    browser_cookie = ngx_list_push(&r->headers_out.headers);
    if (browser_cookie == NULL) {
        return NGX_ERROR;
    }

    browser_cookie->hash = 1;
    browser_cookie->next = NULL;
    ngx_str_set(&browser_cookie->key, "Browser-Cookie");

    // VULNERABLE: Buffer allocation does not account for cookie length
    browser_cookie->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);
    if (browser_cookie->value.data == NULL) {
        browser_cookie->hash = 0;
        return NGX_ERROR;
    }

    // Safari does not fully comply with RFC 2109 regarding cookies.
    if ( r->headers_in.safari && r->headers_in.cookie) {
        // VULNERABLE: Writing cookie data into undersized buffer
        browser_cookie->value.len = ngx_sprintf(browser_cookie->value.data, "\"%xT-%xO\":%s",
                                  r->headers_out.last_modified_time,
                                  r->headers_out.content_length_n,
                                  r->headers_in.cookie->value.data)
                                - browser_cookie->value.data; 
    } else {
        browser_cookie->value.len = ngx_sprintf(browser_cookie->value.data, "\"%xT-%xO\"",
                                  r->headers_out.last_modified_time,
                                  r->headers_out.content_length_n)
                                - browser_cookie->value.data; 
    }
    
    return NGX_OK;
}
```

**Crash Site Location (src/core/ngx_string.c:581)**:
```c
static u_char *
ngx_sprintf_str(u_char *buf, u_char *last, u_char *src, size_t len,
    ngx_uint_t hexadecimal)
{
    static u_char   hex[] = "0123456789abcdef";
    static u_char   HEX[] = "0123456789ABCDEF";

    if (hexadecimal == 0) {
        if (len == (size_t) -1) {
            while (*src && buf < last) {
                *buf++ = *src++;  // Line 581: Buffer overflow write occurs here
            }
        } else {
            len = ngx_min((size_t) (last - buf), len);
            buf = ngx_cpymem(buf, src, len);
        }
    }
    // ... more code
}
```

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-131**: Incorrect Calculation of Buffer Size

## Vulnerability Description

This is a **heap-based buffer overflow vulnerability** caused by insufficient buffer allocation in the `ngx_http_set_browser_cookie` function.

**Root Cause:**
The function allocates a fixed-size buffer (line 5281):
```c
browser_cookie->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);
```

This allocation only accounts for:
- `NGX_OFF_T_LEN`: space for the timestamp format string
- `NGX_TIME_T_LEN`: space for the content length format string
- `3`: space for quotes and formatting characters

However, when Safari browser is detected and a cookie is present (line 5288-5292), the function writes the cookie value into the buffer using `ngx_sprintf`:
```c
if ( r->headers_in.safari && r->headers_in.cookie) {
    browser_cookie->value.len = ngx_sprintf(browser_cookie->value.data, "\"%xT-%xO\":%s",
                              r->headers_out.last_modified_time,
                              r->headers_out.content_length_n,
                              r->headers_in.cookie->value.data)  // Cookie data not accounted for in allocation
                            - browser_cookie->value.data; 
}
```

The allocation **does not include space for `r->headers_in.cookie->value.len`**, leading to a heap buffer overflow when the cookie data is written.

**Impact:**
- Memory corruption (1-byte heap write beyond allocated buffer)
- Potential code execution through heap metadata corruption
- Denial of service through crash

## Patch Analysis

The patch (patch_0.diff) fixes the vulnerability with two changes:

1. **Adds a NULL check** (lines 9-11):
```c
if ( r->headers_in.cookie == NULL ) {
    return NGX_OK;
}
```
This prevents the vulnerability when no cookie is present.

2. **Corrects the buffer allocation** (line 21):
```c
// Before:
browser_cookie->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);

// After:
browser_cookie->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + r->headers_in.cookie->value.len + 3);
```

The fix adds `r->headers_in.cookie->value.len` to the allocation size, ensuring sufficient space for the entire cookie value.

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted HTTP request that:
- Sets the User-Agent to identify as Safari browser (triggers the vulnerable code path)
- Includes a Cookie header with sufficient length to overflow the undersized buffer
- Triggers the overflow when `ngx_sprintf` writes the cookie data into the buffer

## Recommendations

- **Suggested CWEs**: [CWE-122, CWE-787, CWE-131]
- **Vulnerability Name**: Heap Buffer Overflow in nginx Browser Cookie Handler due to Insufficient Buffer Allocation
- **Severity**: High (potential code execution, memory corruption)
- **Origin Classification**: synthetic (custom code not present in official nginx)