# Vulnerability Analysis for cpv_3

## Summary
- **CPV ID**: cpv_3
- **Harness**: tiffcp
- **Vulnerability Type**: Heap buffer overflow (read)
- **Origin**: 1-day
- **Release Date**: 12/15/2022
- **References**: 
  - CVE-2022-3599: https://nvd.nist.gov/vuln/detail/CVE-2022-3599
  - LibTIFF GitLab Issue #398: https://gitlab.com/libtiff/libtiff/-/issues/398
  - LibTIFF v4.5.0 Release Notes: https://libtiff.gitlab.io/libtiff/releases/v4.5.0.html

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: contrib/oss-fuzz/tiffcp.cc:976
- **Vulnerable Function**: `tiffcp` (at line 976, calling `strlen()`)
- **DEDUP Token**: `___interceptor_strlen--tiffcp--LLVMFuzzerTestOneInput`

### Stack Trace
```
READ of size 1 at 0x502000000791 thread T0
SCARINESS: 12 (1-byte-read-heap-buffer-overflow)
    #0 strlen /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:391:5
    #1 tiffcp /src/libtiff/contrib/oss-fuzz/tiffcp.cc:976:57
    #2 LLVMFuzzerTestOneInput /src/libtiff/contrib/oss-fuzz/tiffcp.cc:381:9

Allocation stack trace:
    #0 malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3
    #1 setByteArray /src/libtiff/libtiff/tif_dir.c:52:19
    #2 _TIFFsetNString /src/libtiff/libtiff/tif_dir.c:60:7
    #3 _TIFFVSetField /src/libtiff/libtiff/tif_dir.c:483:4
    #4 TIFFSetField /src/libtiff/libtiff/tif_dir.c:840:11
    #5 TIFFFetchNormalTag /src/libtiff/libtiff/tif_dirread.c:5895:9
    #6 TIFFReadDirectory /src/libtiff/libtiff/tif_dirread.c:4328:13
```

### Memory Allocation Details
- **Allocated size**: 1 byte (insufficient for string operations)
- **Access location**: 0 bytes after the 1-byte region
- **Issue**: Buffer allocated by `setByteArray` doesn't include space for null terminator

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: contrib/oss-fuzz/tiffcp.cc
- **Function**: tiffcp
- **Line Range**: 976-976
- **Column Range**: 57-57

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: libtiff/tif_dir.c
- **Function**: checkInkNamesString
- **Line Range**: 142-166
- **Column Range**: 1-1

### Code Context

**Crash Site (tiffcp.cc:976):**
```c
if (TIFFGetField(in, TIFFTAG_INKNAMES, &inknames)) {
    int inknameslen = strlen(inknames) + 1;
    const char* cp = inknames;
    while (ninks > 1) {
        cp = strchr(cp, '\0');
        cp++;
        inknameslen += (strlen(cp) + 1);  // Line 976 - CRASH HERE
        ninks--;
    }
    TIFFSetField(out, TIFFTAG_INKNAMES, inknameslen, inknames);
}
```

**Root Cause (tif_dir.c:142-166):**
```c
static uint32_t
checkInkNamesString(TIFF* tif, uint32_t slen, const char* s)
{
    TIFFDirectory* td = &tif->tif_dir;
    uint16_t i = td->td_samplesperpixel;

    if (slen > 0) {
        const char* ep = s+slen;
        const char* cp = s;
        for (; i > 0; i--) {
            for (; cp < ep && *cp != '\0'; cp++) {}
            if (cp >= ep)
                goto bad;
            cp++;                // skip \0
        }
        return ((uint32_t)(cp - s));
    }
bad:
    TIFFErrorExt(tif->tif_clientdata, "TIFFSetField",
        "%s: Invalid InkNames value; expecting %"PRIu16" names, found %"PRIu16,
        tif->tif_name,
        td->td_samplesperpixel,
        (uint16_t)(td->td_samplesperpixel-i));
    return (0);
}
```

**Problem**: The `checkInkNamesString()` function validates ink names based on an expected count (`td->td_samplesperpixel`), but if the provided buffer has fewer ink names than expected, or if the strings are not properly null-terminated, it fails validation but still allows allocation of insufficient buffer size.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-125**: Out-of-bounds Read
- **CWE-787**: Out-of-bounds Write

## Vulnerability Description

This vulnerability involves a heap buffer overflow when processing TIFF files containing `TIFFTAG_INKNAMES` metadata. The issue occurs due to improper validation of ink name strings in the `checkInkNamesString()` function.

### Root Cause
The `checkInkNamesString()` function in `libtiff/tif_dir.c` attempts to validate that ink names are properly formatted (null-separated strings), but it relies on an expected count (`td_samplesperpixel`) rather than counting the actual number of ink names present. When a malformed TIFF file provides fewer ink names than expected, or when the ink names buffer is not properly null-terminated, the validation can fail in a way that still allows buffer allocation via `_TIFFsetNString()`.

The `_TIFFsetNString()` function allocates exactly `n` bytes via `setByteArray()`, which calls `_TIFFmalloc(bytes)` where `bytes = n * 1`. This allocation does **not** include space for a null terminator.

### Exploitation Flow
1. Malicious TIFF file contains `TIFFTAG_INKNAMES` with improperly formatted ink names
2. `TIFFReadDirectory()` calls `TIFFFetchNormalTag()` which calls `TIFFSetField()`
3. `_TIFFVSetField()` processes `TIFFTAG_INKNAMES` case
4. `checkInkNamesString()` validates (or fails to validate) the ink names
5. `_TIFFsetNString()` allocates insufficient buffer (e.g., 1 byte)
6. Later, `tiffcp` harness calls `TIFFGetField()` to retrieve ink names
7. Code attempts to parse ink names by calling `strlen(cp)` on each name
8. `strlen()` reads beyond the allocated 1-byte buffer, causing heap buffer overflow

### Impact
- **Denial of Service**: Application crash due to ASAN detection
- **Information Disclosure**: Potential to read heap memory beyond allocated buffer
- **Security Severity**: Medium (CVSS 6.5)

## POV Analysis
The POV file (`pov_0.blob`) is a 284-byte crafted TIFF file that triggers this vulnerability. The file contains malformed `TIFFTAG_INKNAMES` metadata that causes allocation of a 1-byte buffer, which is then read beyond its bounds by `strlen()` operations in the tiffcp harness.

## Patch Analysis

The patch makes significant changes to fix this vulnerability:

### Key Changes

1. **Function Renaming and Logic Change**:
   - Renamed `checkInkNamesString()` → `countInkNamesString()`
   - Changed from validating expected count to actually counting ink names present
   - Return type changed from `uint32_t` to `uint16_t`

2. **Counting Logic**:
   ```c
   // OLD: Loop exactly td_samplesperpixel times
   for (; i > 0; i--) {
       for (; cp < ep && *cp != '\0'; cp++) {}
       if (cp >= ep) goto bad;
       cp++;
   }
   
   // NEW: Count actual ink names present
   do {
       for (; cp < ep && *cp != '\0'; cp++) {}
       if (cp >= ep) goto bad;
       cp++;
       i++;
   } while (cp < ep);
   return (i);  // Return count of actual ink names
   ```

3. **Additional Validation**:
   - Added `TIFFTAG_NUMBEROFINKS` handling
   - Cross-validation between `NumberOfInks` and actual count in `InkNames`
   - Proper synchronization between these two related tags

4. **Error Messages**:
   - Improved error reporting to indicate exact nature of validation failure
   - Changed from "expecting X names, found Y" to "no NUL at buffer end after X inks"

### Fix Location
The fix is applied to:
- **File**: `libtiff/tif_dir.c`
- **Functions**: `checkInkNamesString()` → `countInkNamesString()`, `_TIFFVSetField()` (TIFFTAG_INKNAMES case)
- **Release**: LibTIFF v4.5.0 (December 15, 2022)

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-125, CWE-787]
- **Vulnerability Name**: "LibTIFF TIFFTAG_INKNAMES Heap Buffer Overflow"
- **Mitigation**: Upgrade to LibTIFF v4.5.0 or later, which includes proper validation of ink names and synchronization with NumberOfInks tag