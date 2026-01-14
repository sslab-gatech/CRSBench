# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: svc_dec_fuzzer
- **Vulnerability Type**: Heap-buffer-overflow (WRITE)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (not a publicly disclosed vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 48 at 0x51f000000c80
- **Crash Location**: decoder/ih264d_format_conv.c:497
- **Vulnerable Function**: ih264d_fmt_conv_420sp_to_420sp_swap_uv
- **DEDUP Token**: `__asan_memcpy--ih264d_fmt_conv_420sp_to_420sp_swap_uv--ih264d_format_convert`
- **Scariness Score**: 45 (multi-byte-write-heap-buffer-overflow)

### Stack Trace
```
#0 __asan_memcpy (asan_interceptors_memintrinsics.cpp:63:3)
#1 ih264d_fmt_conv_420sp_to_420sp_swap_uv (ih264d_format_conv.c:497:9)
#2 ih264d_format_convert (ih264d_format_conv.c:765:13)
#3 isvcd_video_decode (isvcd_api.c:5606:21)
#4 Codec::decodeFrame (svc_dec_fuzzer.cpp:375:11)
#5 LLVMFuzzerTestOneInput (svc_dec_fuzzer.cpp:437:22)
```

### Buffer Allocation Context
The overflow occurs when writing to a buffer that was allocated in the fuzzer's `Codec::allocFrame()` function:
- **Allocated size**: 3072 bytes (0x51f000000080 to 0x51f000000c80)
- **Overflow address**: 0x51f000000c80 (0 bytes after the allocated region)
- **Write size**: 48 bytes

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: decoder/ih264d_format_conv.c
- **Function**: ih264d_fmt_conv_420sp_to_420sp_swap_uv
- **Line Range**: 497-497
- **Column Range**: 9-9

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: decoder/svc/isvcd_parse_slice.c
- **Function**: isvcd_parse_decode_slice_ext_nal
- **Line Range**: 768-772
- **Column Range**: 5-60

### Location 3 (root_cause)
- **Type**: root_cause
- **File Path**: decoder/svc/isvcd_parse_slice.c
- **Function**: isvcd_parse_decode_slice
- **Line Range**: 2006-2017
- **Column Range**: 5-60

### Code Context - Crash Site

In `decoder/ih264d_format_conv.c` at line 497, the vulnerable function performs a memcpy operation:

```c
void ih264d_fmt_conv_420sp_to_420sp_swap_uv(UWORD8 *pu1_y_src,
                                            UWORD8 *pu1_uv_src,
                                            UWORD8 *pu1_y_dst,
                                            UWORD8 *pu1_uv_dst,
                                            WORD32 wd,
                                            WORD32 ht,
                                            WORD32 src_y_strd,
                                            WORD32 src_uv_strd,
                                            WORD32 dst_y_strd,
                                            WORD32 dst_uv_strd)
{
    // ... luma copy loop ...
    
    for(i = 0; i < num_rows; i++)
    {
        memcpy(pu1_dst, pu1_src, num_cols);  // LINE 497 - CRASH HERE
        pu1_dst += dst_strd;
        pu1_src += src_strd;
    }
    // ... chroma copy loop ...
}
```

The crash occurs during the luma copy phase when `num_cols` (width) causes writing beyond the allocated buffer.

### Code Context - Root Cause

The root cause is in `decoder/svc/isvcd_parse_slice.c` where display dimensions are set without validation. The patch adds checks to ensure decoder display dimensions match subset sequence dimensions:

**Before the fix** (lines 769-772 in isvcd_parse_decode_slice_ext_nal):
```c
ps_dec->i4_reorder_depth = ps_subset_seq->i4_reorder_depth;

ps_dec->u2_disp_height = ps_subset_seq->u2_disp_height;  // LINE 771
ps_dec->u2_disp_width = ps_subset_seq->u2_disp_width;    // LINE 772
```

**After the fix** (patch adds validation before these assignments):
```c
if(ps_dec->u1_init_dec_flag == 1)
{
    if(ps_dec->u2_disp_height != ps_subset_seq->u2_disp_height) return ERROR_INV_SLICE_HDR_T;
    if(ps_dec->u2_disp_width != ps_subset_seq->u2_disp_width) return ERROR_INV_SLICE_HDR_T;
}

ps_dec->i4_reorder_depth = ps_subset_seq->i4_reorder_depth;
ps_dec->u2_disp_height = ps_subset_seq->u2_disp_height;
ps_dec->u2_disp_width = ps_subset_seq->u2_disp_width;
```

The same fix is applied in `isvcd_parse_decode_slice` at lines 2016-2017.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-1284**: Improper Validation of Specified Quantity in Input

## Vulnerability Description

This is a heap-based buffer overflow vulnerability in the libavc SVC (Scalable Video Coding) decoder. The vulnerability occurs when processing malformed video streams that specify inconsistent display dimensions between the decoder state and the subset sequence parameters.

**Root Cause**: The decoder fails to validate that display dimensions (height and width) match between the initialized decoder state (`ps_dec->u2_disp_height`, `ps_dec->u2_disp_width`) and the subset sequence parameters (`ps_subset_seq->u2_disp_height`, `ps_subset_seq->u2_disp_width`) when the decoder is already initialized (`u1_init_dec_flag == 1`). This allows an attacker to supply a video stream that causes the decoder to use mismatched dimensions.

**Attack Flow**:
1. Attacker crafts a malformed SVC video stream with inconsistent display dimensions
2. The decoder parses the slice header in `isvcd_parse_decode_slice_ext_nal` or `isvcd_parse_decode_slice`
3. Without validation, the decoder updates its display dimensions to the new (potentially incorrect) values
4. During format conversion in `ih264d_format_convert`, the decoder calls `ih264d_fmt_conv_420sp_to_420sp_swap_uv`
5. The format conversion function uses the incorrectly updated dimensions to copy data
6. The copy operation writes beyond the allocated buffer boundary, causing a heap buffer overflow

**Impact**: An attacker can trigger a heap buffer overflow by providing a specially crafted SVC video stream. This could lead to denial of service (crash) or potentially arbitrary code execution depending on the exploit techniques and mitigations in place.

## POV Analysis

The POV file `pov_0.blob` (6180 bytes) is a crafted video input that triggers this vulnerability. It contains a malformed SVC video stream designed to:
- Initialize the decoder with specific display dimensions
- Provide a slice header with different display dimensions
- Cause the decoder to allocate buffers based on the original dimensions
- Force format conversion using the new (larger) dimensions
- Trigger the heap buffer overflow during the memcpy operation

## Patch Analysis

The patch (commit b0117e32b9555e7069c2aef571d921bff22f502f) fixes the vulnerability by adding validation checks in two functions:

**File**: `decoder/svc/isvcd_parse_slice.c`

**Fix in isvcd_parse_decode_slice_ext_nal** (after line 767):
```diff
+    if(ps_dec->u1_init_dec_flag == 1)
+    {
+        if(ps_dec->u2_disp_height != ps_subset_seq->u2_disp_height) return ERROR_INV_SLICE_HDR_T;
+        if(ps_dec->u2_disp_width != ps_subset_seq->u2_disp_width) return ERROR_INV_SLICE_HDR_T;
+    }
```

**Fix in isvcd_parse_decode_slice** (after line 2005):
```diff
+    if(ps_dec->u1_init_dec_flag == 1)
+    {
+        if(ps_dec->u2_disp_height != ps_subset_seq->u2_disp_height) return ERROR_INV_SLICE_HDR_T;
+        if(ps_dec->u2_disp_width != ps_subset_seq->u2_disp_width) return ERROR_INV_SLICE_HDR_T;
+    }
```

The fix ensures that once the decoder is initialized, subsequent slices must use the same display dimensions. If dimensions change, the decoder rejects the slice with an `ERROR_INV_SLICE_HDR_T` error, preventing the buffer overflow.

**Bug References in Patch**:
- OSS-Fuzz Bug 68807
- OSS-Fuzz Bug 69682

These are internal OSS-Fuzz bug IDs and not publicly available CVE entries. The fix was committed on July 11, 2024.

## Origin Classification Rationale

This vulnerability is classified as **synthetic** because:
1. No CVE has been assigned to this vulnerability
2. No public security advisory exists (checked Android Security Bulletins for July and August 2024)
3. The OSS-Fuzz bug IDs (68807, 69682) are internal tracking numbers, not public vulnerability identifiers
4. Web searches for these bug IDs and the commit hash found no public vulnerability databases referencing this issue
5. The fix was merged into the codebase without a corresponding public security disclosure

While this is a real vulnerability found by OSS-Fuzz and fixed in the upstream libavc repository, it was not publicly disclosed or assigned a CVE, making it synthetic in the context of this benchmark.

## Recommendations

### Suggested CWEs
- CWE-122 (Heap-based Buffer Overflow)
- CWE-787 (Out-of-bounds Write)
- CWE-1284 (Improper Validation of Specified Quantity in Input)

### Vulnerability Name
"SVC Decoder Display Dimension Mismatch Heap Buffer Overflow"

### Mitigation Strategies
1. **Input Validation**: Always validate that display dimensions remain consistent across slice headers when the decoder is initialized
2. **Bounds Checking**: Implement comprehensive bounds checking before buffer copy operations
3. **Safe Memory Operations**: Consider using safer memory copy functions that enforce size limits
4. **Fuzzing**: Continue fuzzing video decoders to identify similar dimension mismatch vulnerabilities