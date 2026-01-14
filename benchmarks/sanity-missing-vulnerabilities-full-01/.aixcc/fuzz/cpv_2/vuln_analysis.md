# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: fuzz
- **Vulnerability Type**: Intra-object buffer overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: intra-object-overflow
- **Crash Location**: user.c:5
- **Vulnerable Function**: set_username
- **DEDUP Token**: `__asan_memcpy--set_username--set_user_credentials`

### Stack Trace
```
#0 __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
#1 set_username /src/missing-vulnerabilities/user.c:5:5
#2 set_user_credentials /src/missing-vulnerabilities/auth.cpp:29:5
#3 authenticate_user(unsigned char const*, unsigned long) /src/missing-vulnerabilities/auth.cpp:36:5
```

The crash occurs during a WRITE of size 38 at a stack-allocated object, specifically within the `username` field of the `UserSession` structure. The memory access at offset 112 is inside the `session` variable (frame offset [32, 152)), but overflows the `username` buffer boundary within that object.

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: user.c
- **Function**: set_username
- **Line Range**: 5-5
- **Column Range**: 5-5

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: auth.cpp
- **Function**: UserSession::get_max_copy
- **Line Range**: 39-41
- **Column Range**: 1-1

### Code Context

**Crash Site (user.c:5):**
```c
void set_username(char* username, size_t copy_size, const uint8_t* data) {
    memcpy(username, data, copy_size);  // Line 5 - crash occurs here
}
```

**Root Cause (auth.cpp:39-41):**
```cpp
size_t UserSession::get_max_copy() {
    return sizeof(UserSession) - offsetof(UserSession, username);  // Line 40 - incorrect calculation
}
```

The root cause is in the `get_max_copy()` function which incorrectly calculates the maximum copy size. Instead of limiting to the `username` buffer size (16 bytes), it calculates the space from the `username` field to the end of the entire `UserSession` structure, which includes adjacent fields like `post` and `privilege_level`.

**UserSession Structure (auth.h:9-31):**
```cpp
class UserSession {
    private:
        char session_id[32];
        int pre;
        char username[16];     // Only 16 bytes allocated
        int post;              // Adjacent field - can be overwritten
        PrivilegeLevel privilege_level;
    // ...
};
```

## CWE Classification
- **CWE-787**: Out-of-bounds Write
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **CWE-123**: Write-what-where Condition (within object boundary)

## Vulnerability Description

This is an **intra-object buffer overflow** vulnerability where user-controlled data can overflow the `username` buffer (16 bytes) into adjacent fields within the same `UserSession` object.

**Attack Flow:**
1. The `authenticate_user()` function creates a `UserSession` object on the stack
2. User-controlled data is parsed, extracting a `username_length` field (4 bytes at offset 4)
3. The `get_max_copy()` function incorrectly calculates the maximum copy size as `sizeof(UserSession) - offsetof(UserSession, username)`, which is approximately 72 bytes (total struct size minus offset to username)
4. This allows copying up to 72 bytes into a 16-byte `username` buffer
5. The overflow writes into adjacent fields (`post`, `privilege_level`) within the same object
6. AddressSanitizer detects this as an "intra-object-overflow" because the write stays within the object's boundaries but crosses internal field boundaries

**Root Cause:**
The bug is in `auth.cpp:40` where `get_max_copy()` returns the wrong value:
```cpp
return sizeof(UserSession) - offsetof(UserSession, username);
```

This calculates the space from the `username` field to the end of the struct, not the actual size of the `username` buffer.

**Impact:**
- Memory corruption of adjacent fields (`post`, `privilege_level`)
- Potential privilege escalation if `privilege_level` is overwritten
- Stack corruption leading to undefined behavior

## POV Analysis

The POV file contains:
- Magic key: `0xc0ffee29` (reversed due to endianness)
- Username length: `0x00000026` (38 bytes)
- Payload: 38 bytes of `&` characters (0x26)

This triggers the vulnerability by requesting to copy 38 bytes into the 16-byte `username` buffer, causing a 22-byte overflow into adjacent fields.

## Patch Analysis

The patch fixes the vulnerability in two ways:

**Fix 1 (auth.cpp:20-21):** Correct the `get_max_copy()` calculation
```cpp
size_t UserSession::get_max_copy() {
-    return sizeof(UserSession) - offsetof(UserSession, username);
+    // Limit to username buffer (16 bytes) minus one for null terminator
+    return sizeof(username) - 1;
}
```

This correctly limits the copy size to 15 bytes (leaving room for null terminator).

**Fix 2 (auth.cpp:11):** Add explicit null termination
```cpp
    set_username(session_ptr->get_username(), copy_size, data + 8);
+    // Null-terminate the username to prevent overflow into adjacent fields
+    session_ptr->get_username()[copy_size] = '\0';
```

This ensures the username string is always null-terminated, preventing potential string operation overflows.

## Recommendations
- **Suggested CWEs**: [CWE-787, CWE-119, CWE-123]
- **Vulnerability Name**: Intra-object buffer overflow in UserSession username field
- **Severity**: High (memory corruption, potential privilege escalation)