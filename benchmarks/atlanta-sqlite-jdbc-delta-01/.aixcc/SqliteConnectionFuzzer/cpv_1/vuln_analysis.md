# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: SqliteConnectionFuzzer
- **Vulnerability Type**: AddressSanitizer: bad-free (attempting free on address which was not malloc()-ed)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis

### Error Details
- **Error Type**: AddressSanitizer: bad-free
- **Full Error**: "AddressSanitizer: attempting free on address which was not malloc()-ed: 0x603000363eb0"
- **Crash Location**: NativeDB.c (native JNI code)
- **Vulnerable Function**: `Java_org_sqlite_core_NativeDB__1open_1utf8`
- **DEDUP Token**: "AddressSanitizer: attempting free on address which was not malloc()-ed"

### Stack Trace
```
==16==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x603000363eb0 in thread T0
    #0 0x7fbe7290d40f in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:122
    #1 0x7fbd789ec021 in Java_org_sqlite_core_NativeDB__1open_1utf8 (/tmp/sqlite-3.49.1.1-f3016257-2ff2-40e6-a925-919cece79fcb-libsqlitejdbc.so+0x10021)
    #2 0x7fbe57a0de05  (<unknown module>)

0x603000363eb0 is located 0 bytes inside of 26-byte region [0x603000363eb0,0x603000363eca)
allocated by thread T0 here:
    #0 0x7fbe7290d808 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144
    #1 0x7fbd789eb375  (/tmp/sqlite-3.49.1.1-f3016257-2ff2-40e6-a925-919cece79fcb-libsqlitejdbc.so+0xf375)
```

### Java Stack Trace
The crash occurs during database connection establishment:
```
at app//org.sqlite.core.NativeDB._open_utf8(Native Method)
at app//org.sqlite.core.NativeDB._open(NativeDB.java:82)
at app//org.sqlite.core.DB.open(DB.java:216)
at app//org.sqlite.SQLiteConnection.open(SQLiteConnection.java:269)
at app//org.sqlite.SQLiteConnection.<init>(SQLiteConnection.java:68)
at app//org.sqlite.jdbc3.JDBC3Connection.<init>(JDBC3Connection.java:28)
at app//org.sqlite.jdbc4.JDBC4Connection.<init>(JDBC4Connection.java:19)
at app//org.sqlite.JDBC.createConnection(JDBC.java:106)
at app//org.sqlite.SQLiteConfig.createConnection(SQLiteConfig.java:109)
at app//SqliteConnectionFuzzer.fuzzerTestOneInput(SqliteConnectionFuzzer.java:30)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/main/java/org/sqlite/core/NativeDB.c
- **Function**: utf8JavaByteArrayToUtf8Bytes
- **Line Range**: 265-280
- **Issue**: Buffer allocated without accounting for expansion during Unicode canonicalization

### Code Context (Vulnerable Code - Before Patch)

The vulnerability exists in the `utf8JavaByteArrayToUtf8Bytes` function:

```c
static void utf8JavaByteArrayToUtf8Bytes(JNIEnv *env, jbyteArray utf8bytes, char** bytes, int* nbytes)
{
    jsize utf8bytes_length;
    jsize allocation_size;
    char* buf;

    // ... null checks ...

    utf8bytes_length = (*env)->GetArrayLength(env, (jarray) utf8bytes);

    allocation_size = utf8bytes_length + 1;  // Line 265: Insufficient allocation
    buf = (char*) malloc(allocation_size);
    if (!buf)
    {
        throwex_outofmemory(env);
        return;
    }

    (*env)->GetByteArrayRegion(env, utf8bytes, 0, utf8bytes_length, (jbyte*)buf);

    buf[utf8bytes_length] = '\0';

    char *temp = (char*) malloc(allocation_size);  // Line 277: temp buffer same size as buf
    canonicalize_string_to_ascii(buf, temp);        // Line 278: HEAP BUFFER OVERFLOW HERE
    memcpy(buf, temp, allocation_size);             // Line 279
    free(temp);                                      // Line 280

    *bytes = buf;
    if (nbytes) *nbytes = (int) utf8bytes_length;
}
```

### Root Cause Analysis

The vulnerability is a **heap buffer overflow** caused by insufficient buffer allocation. Here's the issue:

1. **Initial allocation**: The code allocates `allocation_size = utf8bytes_length + 1` bytes
2. **Canonicalization expands characters**: The `canonicalize_string_to_ascii()` function converts UTF-8 Unicode characters to ASCII equivalents, and some single UTF-8 characters expand to multiple ASCII characters:
   - `φ` (phi, U+03C6) → `"phi"` (3 bytes)
   - `ß` (sharp s, U+00DF) → `"ss"` (2 bytes)
   - `€` (euro, U+20AC) → `"EUR"` (3 bytes)

3. **Buffer overflow**: When the input contains characters that expand (like multiple `φ` characters), the `temp` buffer (allocated with the same size as the original UTF-8 input) is too small to hold the expanded ASCII output

4. **Bad-free**: The overflow corrupts heap metadata, leading to an invalid free operation when `free(temp)` is called

## POV Analysis

The POV file contains: `jdbc:sqlite:φφφφφφφφßß`

This is a carefully crafted JDBC URL that triggers the vulnerability:
- Contains 8 phi characters (`φ`, U+03C6) - each expands to 3 ASCII characters (`"phi"`)
- Contains 2 sharp s characters (`ß`, U+00DF) - each expands to 2 ASCII characters (`"ss"`)
- **Expansion calculation**: 
  - 8 × φ (1 byte UTF-8 → 3 bytes ASCII) = 24 bytes (from 8)
  - 2 × ß (2 bytes UTF-8 → 2 bytes ASCII) = 4 bytes (from 4)
  - Net increase: +16 bytes beyond allocated buffer size

This expansion causes a heap buffer overflow when `canonicalize_string_to_ascii()` writes the expanded string into the undersized `temp` buffer.

## Patch Analysis

The patch adds the `estimate_extra_size()` function and reallocates the buffer before canonicalization:

```c
static jsize estimate_extra_size(char* buf)
{
    jsize size = 0;
    for (char* p = buf; *p; p++) {
      if (*p & 0x80)
        // two more bytes are enough
        size += 2;
    }
    return size;
}

static void utf8JavaByteArrayToUtf8Bytes(JNIEnv *env, jbyteArray utf8bytes, char** bytes, int* nbytes)
{
    // ... initial allocation ...
    
    buf[utf8bytes_length] = '\0';

    allocation_size += estimate_extra_size(buf);  // NEW: Estimate expansion
    buf = realloc(buf, allocation_size);           // NEW: Reallocate with extra space

    char *temp = (char*) malloc(allocation_size);  // Now uses expanded size
    canonicalize_string_to_ascii(buf, temp);
    memcpy(buf, temp, allocation_size);
    free(temp);
    
    // ...
}
```

**Fix Strategy**:
1. `estimate_extra_size()` scans the input for UTF-8 multi-byte characters (high bit set)
2. Conservatively estimates 2 extra bytes per multi-byte character
3. Reallocates `buf` with the additional space before canonicalization
4. Allocates `temp` with the expanded size
5. This prevents buffer overflow during canonicalization

## CWE Classification

- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-131**: Incorrect Calculation of Buffer Size

## Vulnerability Description

This is a **heap buffer overflow vulnerability** in the sqlite-jdbc native library's UTF-8 to ASCII canonicalization logic. The vulnerability occurs when processing JDBC connection strings containing Unicode characters that expand during ASCII conversion.

The root cause is in the `utf8JavaByteArrayToUtf8Bytes()` function, which allocates a buffer sized for the UTF-8 input but doesn't account for the character expansion that occurs during `canonicalize_string_to_ascii()`. Certain Unicode characters (φ, ß, €, etc.) expand from single UTF-8 characters to multiple ASCII characters. When the input contains many such characters, writing the expanded output overflows the undersized temporary buffer, corrupting heap metadata and causing a crash when the buffer is freed.

**Impact**: 
- Denial of Service (crash)
- Potential memory corruption
- Exploitable if attacker controls JDBC URL input

**Vulnerability Origin**: This is a **synthetic vulnerability** intentionally injected via commit 8b4f59fa with message "inject oob when handling unicode". It was created for testing/benchmarking purposes and is not a real-world CVE.

## Recommendations

- **Suggested CWEs**: [CWE-122, CWE-787, CWE-131]
- **Vulnerability Name**: "Heap Buffer Overflow in UTF-8 Canonicalization"
- **Classification**: synthetic
- **Severity**: High (causes crash, potential memory corruption)