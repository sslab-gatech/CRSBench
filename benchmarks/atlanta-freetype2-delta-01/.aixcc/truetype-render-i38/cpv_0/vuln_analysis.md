# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: truetype-render-i38
- **Vulnerability Type**: Memory Leak (LeakSanitizer)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: LeakSanitizer: detected memory leaks
- **Crash Location**: src/bdf/bdflib.c:1491
- **Vulnerable Function**: bdf_parse_glyphs_
- **DEDUP Token**: __interceptor_malloc--ft_mem_qalloc--ft_mem_dup

### Stack Trace
The memory leak occurs in the following call stack:
```
#0 malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3
#1 ft_mem_qalloc /src/freetype2-testing/external/freetype2/src/base/ftutil.c:75:15
#2 ft_mem_dup /src/freetype2-testing/external/freetype2/src/base/ftutil.c:184:21
#3 bdf_parse_glyphs_ /src/freetype2-testing/external/freetype2/src/bdf/bdflib.c:1491:12
```

The leak is detected as: **Direct leak of 1 byte(s) in 1 object(s)**

## Vulnerable Code Location(s)

### Location 1 (crash_site and allocation site)
- **Type**: crash_site
- **File Path**: src/bdf/bdflib.c
- **Function**: bdf_parse_glyphs_
- **Line Range**: 1491-1491
- **Column Range**: 12-12

### Location 2 (root_cause - missing free)
- **Type**: root_cause
- **File Path**: src/bdf/bdflib.c
- **Function**: bdf_parse_glyphs_
- **Line Range**: 1448-1453
- **Column Range**: 5-32

### Code Context

**Allocation site (line 1491):**
```c
if ( FT_DUP( p->glyph_name, s, slen + 1 ) )
  goto Exit;
```

**Root cause - missing free in ENDCHAR handler (lines 1447-1453):**
```c
/* Check for the ENDCHAR field. */
if ( _bdf_strncmp( line, "ENDCHAR", 7 ) == 0 )
{
  p->glyph_enc = 0;
  p->flags    &= ~BDF_GLYPH_BITS_;

  goto Exit;
}
```

The issue is that when processing ENDCHAR, the code does not free the previously allocated `p->glyph_name` before clearing the glyph processing state.

## CWE Classification
- **CWE-401**: Missing Release of Memory after Effective Lifetime (Improper Release of Memory Before Removing Last Reference)
- **CWE-772**: Missing Release of Resource after Effective Lifetime

## Vulnerability Description

This is a memory leak vulnerability in the BDF (Bitmap Distribution Format) font parser in FreeType. The vulnerability occurs during the parsing of BDF font files when processing character glyphs.

**Root Cause:**
When the parser encounters a `STARTCHAR` command, it allocates memory to store the glyph name via `FT_DUP` macro (line 1491), which internally calls `ft_mem_dup()` and `malloc()`. However, when an `ENDCHAR` command is subsequently processed (lines 1447-1453), the code clears the glyph parsing state but **fails to free the allocated glyph_name memory**.

**Vulnerability Scenario:**
In a malformed BDF font file with consecutive `STARTCHAR` declarations without proper `ENDCHAR` fields, or when processing multiple glyphs in sequence, each `STARTCHAR` allocates new memory for `p->glyph_name` without freeing the previous allocation. This results in a direct memory leak.

**Impact:**
- Memory exhaustion through repeated processing of specially crafted BDF fonts
- Denial of Service (DoS) through resource exhaustion
- The leak is small (1 byte per glyph in the POV test case), but can accumulate with large or malformed fonts

## POV Analysis

The POV file (`pov_0.blob`) contains a malformed BDF font structure:
```
STARTFONT
FONT \xff
SIZE
FONTBOUNDINGBOX
CHARS
STARTCHAR 
ENDCHAR
STARTCHAR 
```

This input demonstrates the vulnerability by:
1. Declaring a BDF font structure with minimal required headers
2. Starting a character definition with `STARTCHAR` (allocates glyph_name)
3. Ending with `ENDCHAR` (fails to free glyph_name)
4. Starting another character with `STARTCHAR` (potentially overwriting pointer without freeing)

The sanitizer detects the 1-byte leak from the `ft_mem_dup()` allocation that was never freed.

## Patch Analysis

The patch (patch_0.diff) fixes the vulnerability by adding proper memory cleanup:

```diff
@@ -1447,6 +1447,9 @@
     /* Check for the ENDCHAR field. */
     if ( _bdf_strncmp( line, "ENDCHAR", 7 ) == 0 )
     {
+      /* Free unused glyph_name */
+      FT_FREE( p->glyph_name );
+
       p->glyph_enc = 0;
       p->flags    &= ~BDF_GLYPH_BITS_;
```

**Fix:**
The patch adds `FT_FREE( p->glyph_name )` immediately after detecting an `ENDCHAR` command, ensuring that the allocated glyph name memory is properly released before clearing the glyph processing state.

**Effect:**
- Prevents memory leaks during BDF font parsing
- Ensures proper resource cleanup between character definitions
- Maintains correct memory management across multiple glyph processing cycles

## Origin Classification

**Origin: synthetic**

**Reasoning:**
Despite extensive searches, no official CVE, OSV, GHSA, or bug tracker reference was found for this specific vulnerability. The searches included:
- FreeType CVE databases
- GitLab/GitHub commit history with the exact commit hash (5e312bbaf)
- Searches for "bdflib.c glyph_name memory leak ENDCHAR"
- FreeType mailing list archives

Since no concrete evidence of this being a 1-day vulnerability (with official CVE or security advisory) was found, it is classified as **synthetic**.

## Recommendations
- **Suggested CWEs**: [CWE-401, CWE-772]
- **Vulnerability Name**: BDF Font Parser Memory Leak in ENDCHAR Processing
- **Severity**: Low to Medium (Memory leak, potential DoS through resource exhaustion)