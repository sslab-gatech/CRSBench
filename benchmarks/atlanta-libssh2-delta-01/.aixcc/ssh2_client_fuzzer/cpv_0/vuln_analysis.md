# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ssh2_client_fuzzer
- **Vulnerability Type**: Double-free (attempting double-free)
- **Origin**: 1-day
- **Release Date**: 09/10/2024
- **References**: https://github.com/libssh2/libssh2/pull/1452

## Crash Log Analysis
- **Error Type**: AddressSanitizer: attempting double-free
- **Crash Location**: src/kex.c:473
- **Vulnerable Function**: diffie_hellman_sha_algo
- **DEDUP Token**: `__interceptor_free--libssh2_default_free--diffie_hellman_sha_algo`

### Stack Trace

The crash occurs when trying to free the same memory address (0x504000000350) twice:

**First free:**
```
#0 free
#1 libssh2_default_free at src/session.c:86:5
#2 diffie_hellman_sha_algo at src/kex.c:473:13
#3 kex_method_diffie_hellman_group14_key_exchange at src/kex.c:1172:11
#4 kex_method_diffie_hellman_group14_sha1_key_exchange at src/kex.c:1196:12
#5 _libssh2_kex_exchange at src/kex.c:4150:23
...
```

**Second free (causing crash):**
```
#0 free
#1 libssh2_default_free at src/session.c:86:5
#2 diffie_hellman_sha_algo at src/kex.c:473:13
#3 kex_method_diffie_hellman_group14_key_exchange at src/kex.c:1172:11
...
```

**Original allocation:**
```
#0 malloc
#1 libssh2_default_alloc at src/session.c:77:12
#2 _libssh2_copy_string at src/misc.c:924:19
#3 diffie_hellman_sha_algo at src/kex.c:475:12
...
```

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause)
- **Type**: Both crash_site and root_cause (they are the same in this case)
- **File Path**: src/kex.c
- **Function**: diffie_hellman_sha_algo
- **Line Range**: 472-473
- **Column Range**: 13-13

### Code Context

**Vulnerable code (before patch):**
```c
if(session->server_hostkey)
    LIBSSH2_FREE(session, session->server_hostkey);

if(_libssh2_copy_string(session, &buf, &(session->server_hostkey),
                        &host_key_len)) {
    ret = _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                         "Could not copy host key");
    goto clean_exit;
}

session->server_hostkey_len = (uint32_t)host_key_len;
```

**Fixed code (after patch):**
```c
if(session->server_hostkey) {
    LIBSSH2_FREE(session, session->server_hostkey);
    session->server_hostkey = NULL;
    session->server_hostkey_len = 0;
}

if(_libssh2_copy_string(session, &buf, &(session->server_hostkey),
                        &host_key_len)) {
    ret = _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                         "Could not copy host key");
    goto clean_exit;
}

session->server_hostkey_len = (uint32_t)host_key_len;
```

## CWE Classification
- **CWE-415**: Double Free
  - The same memory is freed twice without an intervening reallocation, which can lead to corruption of the internal data structures and potentially code execution.
- **CWE-672**: Operation on a Resource after Expiration or Release
  - The code operates on (frees) a memory resource after it has already been released.

## Vulnerability Description

This is a **double-free vulnerability** in libssh2's Diffie-Hellman key exchange implementation. The vulnerability occurs in the `diffie_hellman_sha_algo` function when handling SSH server hostkeys during the key exchange process.

### Root Cause

The function frees `session->server_hostkey` if it exists but fails to set the pointer to NULL and reset the length field to 0. When the key exchange function is called multiple times (which can happen during SSH session negotiation, especially when the server sends multiple key exchange attempts or when optimistic key exchange fails), the same memory address gets freed again, causing a double-free condition.

### Triggering Scenario

The double-free is triggered when:
1. The `diffie_hellman_sha_algo` function is called during initial key exchange
2. Memory is allocated for `session->server_hostkey` via `_libssh2_copy_string`
3. The function is called again (e.g., after burning an optimistic kexinit packet - see lines 411-435)
4. The code attempts to free `session->server_hostkey` again at line 473
5. Since the pointer was not nullified after the first free, the check `if(session->server_hostkey)` passes
6. The same memory is freed twice, triggering AddressSanitizer's double-free detection

### Impact

- **Denial of Service**: Immediate crash when the vulnerability is triggered
- **Memory Corruption**: Double-free can corrupt heap metadata, potentially leading to arbitrary code execution
- **Security Impact**: Exploitable during SSH handshake process, allowing remote unauthenticated attackers to crash SSH clients

## POV Analysis

The POV file (`pov_0.blob`) is a binary test case that triggers the vulnerability. From the hex dump analysis:

- Begins with "SSH-" indicating an SSH protocol message
- Contains malformed or specially crafted key exchange negotiation data
- Includes multiple key exchange algorithm strings and corrupted packet structures
- Designed to trigger multiple calls to the key exchange handling code, causing the double-free condition

The fuzzer-generated input crafts an SSH handshake sequence that causes the key exchange to be processed multiple times, exposing the double-free bug.

## Patch Analysis

The fix (PR #1452, commit b3465418) addresses the vulnerability by adding proper pointer nullification and length reset:

**Changes made:**
1. Added braces to the `if(session->server_hostkey)` block for clarity
2. Added `session->server_hostkey = NULL;` after freeing
3. Added `session->server_hostkey_len = 0;` to reset the length field

**Why this fixes the vulnerability:**
- Setting the pointer to NULL ensures subsequent frees are safe (freeing NULL is a no-op)
- Resetting the length prevents potential use-after-free issues where the length might be checked
- Follows proper memory management practices for dangling pointer prevention

## Recommendations

### For vuln.yaml:
- **Suggested CWEs**: [CWE-415, CWE-672]
- **Vulnerability name**: "Double-free in Diffie-Hellman hostkey handling during SSH key exchange"
- **Origin**: 1-day (discovered through fuzzing and fixed in PR #1452)
- **Release Date**: 09/10/2024 (date PR #1452 was merged)
- **Reference**: https://github.com/libssh2/libssh2/pull/1452

### Location Details:
- **crash_site**: src/kex.c, function: diffie_hellman_sha_algo, lines: 472-473
- **root_cause**: Same as crash_site (the missing NULL assignment is the root cause)