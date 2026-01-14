# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: fuzz_probe_analyze
- **Vulnerability Type**: Global buffer overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: global-buffer-overflow
- **Crash Location**: src/media_tools/av_parsers.c:4523:9
- **Vulnerable Function**: gf_mp3_bit_rate
- **DEDUP Token**: gf_mp3_bit_rate--get_info_from_frame--get_info_for_all_streams
- **Operation**: READ of size 4
- **Address Details**: 0 bytes after global variable 'bitrate_table' (300 bytes total)

### Stack Trace
```
#0 0x557918471603 in gf_mp3_bit_rate /src/gpac/src/media_tools/av_parsers.c:4523:9
#1 0x5579185c1100 in get_info_from_frame /src/gpac/src/media_tools/mpeg2_ps.c:1014:19
#2 0x5579185c1100 in get_info_for_all_streams /src/gpac/src/media_tools/mpeg2_ps.c:1206:4
#3 0x5579185c1100 in mpeg2ps_scan_file /src/gpac/src/media_tools/mpeg2_ps.c:1371:2
#4 0x5579185c1100 in mpeg2ps_init /src/gpac/src/media_tools/mpeg2_ps.c:1628:2
#5 0x557917927afd in m2psdmx_process /src/gpac/src/filters/dmx_mpegps.c:327:13
#6 0x5579177f4878 in gf_filter_process_task /src/gpac/src/filter_core/filter.c:3027:7
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/media_tools/av_parsers.c
- **Function**: gf_mp3_bit_rate
- **Line Range**: 4523-4523
- **Column Range**: 9-9

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/media_tools/av_parsers.c
- **Function**: gf_mp3_bit_rate
- **Line Range**: 4505-4523
- **Column Range**: 1-40

### Code Context

The vulnerable code in `gf_mp3_bit_rate` function (line 4501-4524):

```c
u32 gf_mp3_bit_rate(u32 hdr)
{
	u8 version = gf_mp3_version(hdr);
	u8 layer = gf_mp3_layer(hdr);
	u8 bitRateIndex = (hdr >> 12) & 0xF;  // Line 4505: Extract 4-bit index (0-15)
	u32 lidx;
	/*MPEG-1*/
	if (version & 1) {
		if (!layer) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_CODING, ("[MPEG-1/2 Audio] layer index not valid\n"));
			return 0;
		}
		lidx = layer - 1;
	}
	/*MPEG-2/2.5*/
	else {
		lidx = 3 + (layer >> 1);
	}
	if (lidx>4) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_CODING, ("[MPEG-1/2 Audio] layer index not valid\n"));
		return 0;
	}
	return bitrate_table[lidx][bitRateIndex];  // Line 4523: VULNERABLE - No bounds check on bitRateIndex
}
```

The `bitrate_table` definition (lines 4478-4498):

```c
static
u32 const bitrate_table[5][15] = {  // 5 rows, 15 columns (indices 0-14)
	/* MPEG-1 */
	{	0,  32000,  64000,  96000, 128000, 160000, 192000, 224000,  /* Layer I   */
		256000, 288000, 320000, 352000, 384000, 416000, 448000
	},
	{	0,  32000,  48000,  56000,  64000,  80000,  96000, 112000,  /* Layer II  */
		128000, 160000, 192000, 224000, 256000, 320000, 384000
	},
	{	0,  32000,  40000,  48000,  56000,  64000,  80000,  96000,  /* Layer III */
		112000, 128000, 160000, 192000, 224000, 256000, 320000
	},
	/* MPEG-2 LSF */
	{	0,  32000,  48000,  56000,  64000,  80000,  96000, 112000,  /* Layer I   */
		128000, 144000, 160000, 176000, 192000, 224000, 256000
	},
	{	0,   8000,  16000,  24000,  32000,  40000,  48000,  56000,  /* Layers    */
		64000,  80000,  96000, 112000, 128000, 144000, 160000
	} /* II & III  */
};
```

## CWE Classification
- **CWE-125**: Out-of-bounds Read - Reading data past the end of a buffer
- **CWE-787**: Out-of-bounds Write (related) - Memory access violations
- **CWE-129**: Improper Validation of Array Index - Missing bounds check on array index

## Vulnerability Description

This is a **global buffer overflow** vulnerability in the `gf_mp3_bit_rate` function in GPAC's MP3 audio parser. The vulnerability occurs due to insufficient bounds checking on the `bitRateIndex` parameter before using it as an array index.

### Root Cause

At line 4505, the function extracts a 4-bit value from the MP3 header to use as `bitRateIndex`:
```c
u8 bitRateIndex = (hdr >> 12) & 0xF;  // Can be 0-15
```

This 4-bit value can range from 0 to 15. However, the `bitrate_table` array is defined with only 15 columns (indices 0-14). The code validates the row index (`lidx`) to ensure it doesn't exceed 4, but **fails to validate `bitRateIndex`** before using it at line 4523:

```c
return bitrate_table[lidx][bitRateIndex];  // Out-of-bounds when bitRateIndex == 15
```

When a malformed MP3 file contains a bitrate index value of 15, the code attempts to access `bitrate_table[lidx][15]`, which is out of bounds, resulting in a 4-byte READ past the end of the global `bitrate_table` buffer.

### Impact

- **Confidentiality**: Potential information disclosure by reading 4 bytes past the buffer
- **Availability**: Crash/denial of service (as demonstrated by the POV)
- **Integrity**: No direct integrity impact, but could be part of a larger exploit chain
- **Attack Vector**: Remote - Can be triggered by processing a malicious MPEG file

### Severity Assessment
- **SCARINESS Score**: 17 (from crash log)
- **Type**: 4-byte-read-global-buffer-overflow
- **Exploitability**: Medium - Requires crafted MPEG input file
- **Reliability**: High - Consistently triggered with specific bitrate index

## POV Analysis

The proof-of-vulnerability test case (`pov_0.blob`) is an MPEG sequence file (MPEG-1 system multiplex format) that has been crafted to trigger this vulnerability. The file contains:

- XML header: `<?xml version="1.0" encoding="UTF-8"?><GPACInspect>`
- A malformed MP3 audio frame with:
  - Invalid samplerate index (logged as: `[MPEG-1/2 Audio] Samplerate index not valid`)
  - Bitrate index set to 15 (0xF), which exceeds the valid range of 0-14

When GPAC's probe/analyze functionality processes this file, it:
1. Detects it as an MPEG-2 PS (program stream) format
2. Calls `mpeg2ps_init` → `mpeg2ps_scan_file` → `get_info_for_all_streams` → `get_info_from_frame`
3. Attempts to parse MP3 frame information by calling `gf_mp3_bit_rate`
4. Triggers the out-of-bounds read when accessing `bitrate_table[lidx][15]`

## Patch Analysis

The patch adds a bounds check for `bitRateIndex` before the array access:

```diff
@@ -4520,6 +4520,10 @@ u32 gf_mp3_bit_rate(u32 hdr)
 		GF_LOG(GF_LOG_ERROR, GF_LOG_CODING, ("[MPEG-1/2 Audio] layer index not valid\n"));
 		return 0;
 	}
+	if (bitRateIndex>14) {
+		GF_LOG(GF_LOG_ERROR, GF_LOG_CODING, ("[MPEG-1/2 Audio] Bitrate index not valid\n"));
+		return 0;
+	}
 	return bitrate_table[lidx][bitRateIndex];
 }
```

### Fix Analysis

The patch correctly addresses the root cause by:

1. **Adding validation** for `bitRateIndex` before array access
2. **Checking the upper bound** - Rejects values > 14 (valid range is 0-14 for 15 elements)
3. **Logging the error** - Provides diagnostic information for debugging
4. **Safe failure** - Returns 0 to indicate an invalid bitrate instead of crashing

This is a **defensive programming fix** that validates input before using it as an array index, which is the proper way to prevent this class of vulnerabilities.

### Location Analysis

- **Crash Site**: Line 4523 (where the out-of-bounds read occurs)
- **Root Cause**: Lines 4505-4523 (missing validation after extracting bitRateIndex)
- **Fix Location**: Between line 4522 and 4523 (added validation before array access)

The patch location matches the root cause location, as it adds the necessary validation check immediately before the vulnerable array access.

## Recommendations

### For vuln.yaml Generation:
- **Suggested CWEs**: [CWE-125, CWE-787, CWE-129]
- **Vulnerability Name**: "Global buffer overflow in gf_mp3_bit_rate due to unchecked bitrate index"
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **Locations**:
  - crash_site: `src/media_tools/av_parsers.c:4523:9` (function: gf_mp3_bit_rate)
  - root_cause: `src/media_tools/av_parsers.c:4505-4523:1-40` (function: gf_mp3_bit_rate, specifically the missing validation)

### Additional Security Considerations:
1. All array indices extracted from untrusted input should be validated before use
2. Consider using safe array access functions that perform bounds checking
3. Review other instances of similar patterns in the codebase (parsing functions that extract indices from headers)
4. Add fuzzing tests that specifically target boundary values in media format headers

---

**Analysis Complete**: This vulnerability is a classic example of improper input validation leading to out-of-bounds memory access. The fix is straightforward and effective, adding the missing bounds check that should have been present from the start.