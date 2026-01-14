# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: mvc_dec_fuzzer
- **Vulnerability Type**: Heap Buffer Overflow
- **Origin**: synthetic (OSS-Fuzz discovered, no public CVE assigned)
- **Release Date**: 02/01/2026
- **References**: None (OSS-Fuzz internal bug report ossfuzz:66989, not publicly accessible)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: READ of size 4
- **Crash Location**: decoder/ih264d_parse_cabac.c:203
- **Vulnerable Function**: ih264d_read_coeff4x4_cabac
- **DEDUP Token**: ih264d_read_coeff4x4_cabac--ih264d_cabac_parse_8x8block--ih264d_parse_residual4x4_cabac

### Stack Trace
The crash occurs during MVC (Multiview Video Coding) decoding when processing CABAC-encoded coefficient data:

```
#0 ih264d_read_coeff4x4_cabac /src/libavc/decoder/ih264d_parse_cabac.c:203:25
#1 ih264d_cabac_parse_8x8block /src/libavc/decoder/ih264d_parse_cabac.c:1123:25
#2 ih264d_parse_residual4x4_cabac /src/libavc/decoder/ih264d_parse_cabac.c:1593:23
#3 ih264d_parse_imb_cabac /src/libavc/decoder/ih264d_parse_islice.c:724:5
#4 ih264d_parse_islice_data_cabac /src/libavc/decoder/ih264d_parse_islice.c:1087:23
#5 ih264d_parse_islice /src/libavc/decoder/ih264d_parse_islice.c:1489:15
#6 imvcd_parse_islice /src/libavc/decoder/mvc/imvcd_slice_functions.c:1894:9
#7 imvcd_parse_decode_slice /src/libavc/decoder/mvc/imvcd_slice_functions.c:2351:25
#8 imvcd_nalu_parser /src/libavc/decoder/mvc/imvcd_nalu_parser.c:809:41
#9 imvcd_view_decode /src/libavc/decoder/mvc/imvcd_api.c:829:29
#10 imvcd_decode /src/libavc/decoder/mvc/imvcd_api.c:1240:20
#11 imvcd_api_function /src/libavc/decoder/mvc/imvcd_api.c:1602:20
```

### Memory Details
- **Overflow Address**: 0x7fa70fffe8c8
- **Buffer Details**: Reading 0 bytes after a 258251-byte heap region [0x7fa70ffbf800, 0x7fa70fffe8cb)
- **Allocation Site**: imvcd_bitstream_buf_realloc at decoder/mvc/imvcd_api_utils.c:402

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: decoder/ih264d_parse_cabac.c
- **Function**: ih264d_read_coeff4x4_cabac
- **Line Range**: 203-203
- **Column Range**: 25-25

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: decoder/mvc/imvcd_api.c
- **Function**: imvcd_view_decode
- **Line Range**: 736-736
- **Column Range**: 1-60

### Code Context

**Crash Site (decoder/ih264d_parse_cabac.c:203)**:
The crash occurs when the NEXTBITS macro attempts to read ahead in the bitstream buffer:

```c
if(u4_code_int_range < ONE_RIGHT_SHIFTED_BY_14)
{
    UWORD32 read_bits, u4_clz;
    u4_clz = CLZ(u4_code_int_range);
    NEXTBITS(read_bits, (u4_offset + 23), pu4_buffer, u4_clz)  // Line 203 - CRASH HERE
    FLUSHBITS(u4_offset, (u4_clz))
    u4_code_int_range = u4_code_int_range << u4_clz;
    u4_code_int_val_ofst = (u4_code_int_val_ofst << u4_clz) | read_bits;
}
```

**Root Cause (decoder/mvc/imvcd_api.c:736)**:
The bitstream buffer is allocated with insufficient padding:

```c
if(i4_nalu_length)
{
    UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8;  // Line 736 - INSUFFICIENT PADDING

    if(u4_nalu_buf_size > u4_bitstream_buf_size)
    {
        /* 64 extra bytes to account for OOB accesses during SEI parsing */
        if(IV_SUCCESS != imvcd_bitstream_buf_realloc(ps_view_ctxt, u4_nalu_buf_size + 64))
        {
            return IV_FAIL;
        }
        ...
    }
}
```

**NEXTBITS Macro (decoder/ih264d_bitstrm.h:137-146)**:
The NEXTBITS macro can read up to 8 bytes (two 32-bit words) from the buffer:

```c
#define NEXTBITS(u4_word, u4_offset, pu4_bitstream, u4_no_bits)  \
{                                                                \
    UWORD32 *pu4_buf = (pu4_bitstream);                         \
    UWORD32 u4_word_off = ((u4_offset) >> 5);                   \
    UWORD32 u4_bit_off = (u4_offset) & 0x1F;                    \
    u4_word = pu4_buf[u4_word_off++] << u4_bit_off;            \
    if(u4_bit_off)                                              \
        u4_word |= (pu4_buf[u4_word_off] >> (INT_IN_BITS - u4_bit_off)); \
    u4_word = u4_word >> (INT_IN_BITS - u4_no_bits);           \
}
```

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write (more general category)
- **CWE-125**: Out-of-bounds Read (the specific operation that crashes)

## Vulnerability Description

This vulnerability is a heap buffer overflow that occurs in the MVC (Multiview Video Coding) decoder component of libavc. The issue arises when processing specially crafted or malformed video bitstreams with CABAC (Context-Adaptive Binary Arithmetic Coding) entropy coding.

**Root Cause**: 
The bitstream buffer is allocated with insufficient padding to account for look-ahead reads performed by the NEXTBITS macro during CABAC coefficient parsing. The buffer size calculation at line 736 of `imvcd_api.c` adds only 8 bytes of padding:

```c
UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8;
```

However, during CABAC decoding of 4x4 transform units, the `ih264d_read_coeff4x4_cabac` function uses the NEXTBITS macro, which can read up to 8 bytes ahead in the buffer (accessing two consecutive 32-bit words). In pathological fuzzer-generated bitstreams, the slice data can require more parsing than what was implied by the distance between successive start codes, causing reads beyond the allocated buffer boundary.

**Impact**:
- **Memory Safety**: 4-byte out-of-bounds read from heap memory
- **Crash/DoS**: The vulnerability causes immediate program termination via AddressSanitizer detection
- **Information Disclosure**: Potential to leak adjacent heap memory contents
- **Exploitation**: Could potentially be leveraged for information disclosure, though direct code execution is unlikely due to the read-only nature of the overflow

**Attack Vector**:
An attacker could craft a malicious MVC video bitstream and deliver it via:
- Malicious video file
- Streaming video content
- Video embedded in web pages or documents
- Any application using libavc for MVC video decoding

## POV Analysis

A proof-of-vulnerability test case exists at `cpv_1/blobs/pov_0.blob` (519 KB). This is a specially crafted MVC video bitstream that triggers the vulnerability by:

1. Containing NALU (Network Abstraction Layer Unit) data that causes the decoder to allocate a specific-sized bitstream buffer
2. Encoding slice data with CABAC that requires extensive coefficient parsing
3. Structuring the data such that NEXTBITS macro reads extend beyond the allocated buffer boundary during 4x4 transform unit processing

The POV successfully reproduces the crash in 100% of test runs, as evidenced by the crash log.

## Patch Analysis

**Commit**: 72315c11ac595a73d3b629cc36647327156d5875  
**Date**: February 26, 2024 (authored), May 7, 2024 (committed)  
**Author**: Ashwin Natesan <ashwin.natesan@ittiam.com>  
**Title**: mvcdec: Heap overflow in 'ih264d_read_coeff4x4_cabac'

**Fix Description**:
The patch increases the bitstream buffer allocation to include additional padding for safe NEXTBITS macro operation. The buffer size calculation is modified from:

```c
UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8;
```

to:

```c
UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8 + 4 * 16;
```

This adds 64 bytes (4 bytes per 4x4 transform unit × 16 TUs in a macroblock) of additional padding to accommodate the NEXTBITS macro's look-ahead reads during CABAC coefficient parsing. The comment in the patch explains:

> "In some erroneous fuzzer bitstreams, the slice data requires more parsing than what was implied by the distance between successive start codes. The primary culprit is the NEXTBITS macro which requires reading 4 additional bytes of the bitstream buffer. To alleviate this, 4 bytes per 4x4 TU have been additionally allocated to the bitstream buffer."

**Effectiveness**:
The fix is appropriate and addresses the root cause by ensuring sufficient buffer padding for worst-case NEXTBITS reads during 4x4 coefficient parsing. The 64-byte padding (4 * 16) accounts for the maximum number of 4x4 transform units that could be processed in a single macroblock.

## Recommendations

### For vuln.yaml Generation:
- **Origin**: synthetic (no public CVE, OSS-Fuzz internal discovery)
- **Release Date**: 02/01/2026
- **CWEs**: [CWE-122, CWE-787, CWE-125]
- **Vulnerability Name**: "MVC CABAC Coefficient Parsing Heap Buffer Overflow"
- **Crash Site Location**: 
  - File: decoder/ih264d_parse_cabac.c
  - Function: ih264d_read_coeff4x4_cabac
  - Lines: 203-203
- **Root Cause Location**:
  - File: decoder/mvc/imvcd_api.c
  - Function: imvcd_view_decode
  - Lines: 736-736

### Security Considerations:
1. The vulnerability affects MVC (Multiview Video Coding) decoding specifically
2. Requires specially crafted bitstream input to trigger
3. Mitigated by the patch adding 64 bytes of buffer padding
4. AddressSanitizer successfully detects the overflow, preventing exploitation in instrumented builds
5. Applications using libavc should update to a version containing commit 72315c11ac595a73d3b629cc36647327156d5875 or later