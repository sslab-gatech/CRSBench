# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: tiff_open
- **Vulnerability Type**: Out-of-memory (excessive memory allocation)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: libFuzzer: out-of-memory
- **Crash Location**: libtiff/tif_dirread.c:6498
- **Vulnerable Function**: allocChoppedUpStripArrays
- **DEDUP Token**: `__sanitizer_print_stack_trace--fuzzer::PrintStackTrace()--fuzzer::Fuzzer::HandleMalloc(unsigned long)`

### Stack Trace
```
==14== ERROR: libFuzzer: out-of-memory (malloc(3489662144))
   To change the out-of-memory limit use -rss_limit_mb=<N>

    #8 0x556cae91fa33 in _TIFFCheckRealloc /src/libtiff/libtiff/tif_aux.c:106:8
    #9 0x556cae91fa33 in _TIFFCheckMalloc /src/libtiff/libtiff/tif_aux.c:122:9
    #10 0x556cae909854 in allocChoppedUpStripArrays /src/libtiff/libtiff/tif_dirread.c:6498:29
    #11 0x556cae8e88e9 in TIFFReadDirectory /src/libtiff/libtiff/tif_dirread.c:4650:13
    #12 0x556cae90c3a3 in TIFFClientOpen /src/libtiff/libtiff/tif_open.c:483:8
    #13 0x556cae91ef8c in TIFFFdOpen /src/libtiff/libtiff/tif_unix.c:209:8
    #14 0x556cae91ef8c in TIFFOpen /src/libtiff/libtiff/tif_unix.c:248:8
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: libtiff/tif_dirread.c
- **Function**: allocChoppedUpStripArrays
- **Line Range**: 6498-6501
- **Column Range**: 5-74

The root cause is the lack of validation before attempting to allocate memory. The function attempts to allocate memory based on the `nstrips` parameter derived from potentially malicious TIFF file data without checking if the requested allocation size is reasonable relative to the file size.

### Code Context
```c
static void allocChoppedUpStripArrays(TIFF* tif, uint32_t nstrips,
                                      uint64_t stripbytes, uint32_t rowsperstrip)
{
    TIFFDirectory *td = &tif->tif_dir;
    uint64_t bytecount;
    uint64_t offset;
    uint64_t last_offset;
    uint64_t last_bytecount;
    uint32_t i;
    uint64_t *newcounts;
    uint64_t *newoffsets;

    offset = TIFFGetStrileOffset(tif, 0);
    last_offset = TIFFGetStrileOffset(tif, td->td_nstrips-1);
    last_bytecount = TIFFGetStrileByteCount(tif, td->td_nstrips-1);
    if( last_offset > UINT64_MAX - last_bytecount ||
        last_offset + last_bytecount < offset )
    {
        return;
    }
    bytecount = last_offset + last_bytecount - offset;

    // VULNERABLE: No validation of allocation size relative to file size
    newcounts = (uint64_t*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint64_t),
                                             "for chopped \"StripByteCounts\" array");
    newoffsets = (uint64_t*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint64_t),
                                              "for chopped \"StripOffsets\" array");
    // ...
}
```

## CWE Classification
- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-789**: Memory Allocation with Excessive Size Value

## Vulnerability Description

This vulnerability occurs when a maliciously crafted TIFF file with invalid directory entries causes the `allocChoppedUpStripArrays()` function to attempt to allocate an excessive amount of memory (3.4 GB in the crash log).

**Root Cause**: The function accepts a `nstrips` parameter derived from TIFF file metadata without proper validation. When a crafted TIFF file contains an abnormally large value for the number of strips, the function attempts to allocate `nstrips * sizeof(uint64_t) * 2` bytes of memory without checking if this allocation size is reasonable relative to the actual file size.

**Attack Vector**: 
1. Attacker crafts a TIFF file with malformed directory entries specifying an extremely large number of strips
2. The file is parsed by `TIFFReadDirectory()` which calls `allocChoppedUpStripArrays()`
3. The function attempts to allocate ~3.4 GB for strip arrays
4. This causes an out-of-memory condition, leading to denial of service

**Impact**: Denial of service through memory exhaustion. An attacker can cause applications processing TIFF files to crash or become unresponsive by providing relatively small crafted TIFF files (< 400 KB).

## POV Analysis

The POV file `pov_0.blob` is a 379-byte crafted TIFF file that triggers this vulnerability. The crash log shows warnings about:
- Invalid TIFF directory with unsorted tags
- Multiple unknown field tags (464, 0, 22, 13567, 6912, 7168, 48830, 18432)
- Invalid data type for StripByteCounts tag
- Invalid InkNames value

These malformed entries are designed to cause the parser to calculate an extremely large `nstrips` value, triggering the excessive memory allocation.

## Patch Analysis

The patch adds validation checks using `TIFFGetFileSize()` before attempting large memory allocations in multiple locations within `tif_dirread.c`:

1. **allocChoppedUpStripArrays** (lines 6557-6571): Checks that `allocsize = nstrips * sizeof(uint64_t) * 2` doesn't exceed file size
2. **TIFFReadDirEntryArrayWithLimit** (lines 1199-1211): Validates datasize against file size
3. **EstimateStripByteCounts** (lines 4933-4945): Validates strip byte count allocation size
4. **TIFFFetchDirectory** (two locations, lines 5191-5203 and 5306-5318): Validates directory allocation size
5. **TIFFFetchStripThing** (lines 6448-6462): Validates strip array allocation size

The fix implements a defensive strategy: before allocating memory based on file metadata, verify that the requested allocation size is not larger than the entire file size. This prevents malformed TIFF files from triggering excessive memory allocations.

## Recommendations

- **Suggested CWEs**: [CWE-770, CWE-400, CWE-789]
- **Vulnerability Name**: LibTIFF Excessive Memory Allocation in Strip Array Processing
- **Severity**: Medium to High (DoS via memory exhaustion with small crafted input)
- **Mitigation**: Apply the patch that adds file size validation before memory allocation in TIFF directory reading functions