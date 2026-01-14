# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: libjpeg_djpeg_fuzzer
- **Vulnerability Type**: Heap-buffer-overflow (Out-of-bounds Read)
- **Origin**: 1-day
- **Release Date**: 11/29/2018
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2018-19664
  - https://github.com/libjpeg-turbo/libjpeg-turbo/issues/305

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: wrbmp.c:145
- **Vulnerable Function**: put_pixel_rows
- **DEDUP Token**: Not explicitly provided in crash log
- **Crash Details**: READ of size 8 at 0x5100000000f7, accessing 0 bytes after 183-byte region

### Stack Trace
```
#0 0x5559c19c00b7 in put_pixel_rows /src/libjpeg-turbo/wrbmp.c:145:19
#1 0x5559c18d21a2 in LLVMFuzzerTestOneInput /src/libjpeg_djpeg_fuzzer.cc:62:9
```

The allocation trace shows:
```
#0 0x5559c189278f in malloc
#1 0x5559c19b003f in alloc_large /src/libjpeg-turbo/jmemmgr.c:391:29
#2 0x5559c19b056d in alloc_sarray /src/libjpeg-turbo/jmemmgr.c:475:27
#3 0x5559c19bdd95 in jinit_write_bmp /src/libjpeg-turbo/wrbmp.c:550:22
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: wrbmp.c
- **Function**: put_pixel_rows
- **Line Range**: 145-145
- **Column Range**: 19-19

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: wrbmp.c
- **Function**: jinit_write_bmp
- **Line Range**: 509-511
- **Column Range**: 1-50

### Code Context

**Crash Site (wrbmp.c:145):**
```c
} else if (cinfo->out_color_space == JCS_CMYK) {
  for (col = cinfo->output_width; col > 0; col--) {
    /* can omit GETJSAMPLE() safely */
    JSAMPLE c = *inptr++, m = *inptr++, y = *inptr++, k = *inptr++;  // Line 145
    cmyk_to_rgb(c, m, y, k, outptr + 2, outptr + 1, outptr);
    outptr += 3;
  }
}
```

**Root Cause (wrbmp.c:509-511 - before patch):**
```c
} else if (cinfo->out_color_space == JCS_RGB565 ||
           cinfo->out_color_space == JCS_CMYK) {
  dest->pub.put_pixel_rows = put_pixel_rows;
}
```

**Root Cause (after patch):**
```c
} else if (!cinfo->quantize_colors &&
           (cinfo->out_color_space == JCS_RGB565 ||
            cinfo->out_color_space == JCS_CMYK)) {
  dest->pub.put_pixel_rows = put_pixel_rows;
}
```

## CWE Classification
- **CWE-125**: Out-of-bounds Read
- **CWE-122**: Heap-based Buffer Overflow (Read)
- **CWE-787**: Out-of-bounds Write (general category)

## Vulnerability Description

This vulnerability (CVE-2018-19664) is a heap-based buffer over-read in libjpeg-turbo 2.0.1 occurring in the `put_pixel_rows` function in `wrbmp.c`.

**Root Cause:**
The vulnerability occurs when color quantization is enabled (`cinfo->quantize_colors == 1`) in combination with non-RGB color spaces (specifically JCS_CMYK or JCS_RGB565). When quantization is enabled, `jpeg_calc_output_dimensions()` sets `cinfo->output_components` to 1, indicating that the output buffer contains only 1 component per pixel. However, the `jinit_write_bmp` function incorrectly assigns `put_pixel_rows` as the output handler for CMYK and RGB565 color spaces without checking if quantization is enabled.

**The Problem:**
The `put_pixel_rows` function at line 145 attempts to read 4 components (c, m, y, k) from the input buffer when processing CMYK data:
```c
JSAMPLE c = *inptr++, m = *inptr++, y = *inptr++, k = *inptr++;
```

However, the buffer was allocated with `row_width` based on `output_components = 1` (when quantization is on), meaning only 1 byte per pixel is available. This causes the function to read beyond the allocated buffer boundary, resulting in a heap-buffer-overflow.

**Impact:**
- Heap out-of-bounds read
- Potential information disclosure
- Can be triggered by processing a specially crafted JPEG file with djpeg utility
- The crash log shows a READ of size 8 at an address 0 bytes after the allocated 183-byte region

## POV Analysis

The POV file `pov_0.blob` (9756 bytes) is a crafted JPEG file that triggers the vulnerability. The crash log indicates:
- "Corrupt JPEG data: 117 extraneous bytes before marker 0xdb"
- This suggests the POV is a malformed JPEG designed to trigger the quantization + CMYK color space condition

## Patch Analysis

The patch fixes the root cause by adding a check for `!cinfo->quantize_colors` before allowing `put_pixel_rows` to be used with JCS_RGB565 or JCS_CMYK color spaces:

**Changed lines in wrbmp.c (lines 509-511):**
```diff
-  } else if (cinfo->out_color_space == JCS_RGB565 ||
-             cinfo->out_color_space == JCS_CMYK) {
+  } else if (!cinfo->quantize_colors &&
+             (cinfo->out_color_space == JCS_RGB565 ||
+              cinfo->out_color_space == JCS_CMYK)) {
     dest->pub.put_pixel_rows = put_pixel_rows;
```

This ensures that when quantization is enabled (making `output_components = 1`), the code will fall through to the error case (`ERREXIT(cinfo, JERR_BMP_COLORSPACE)`), preventing the mismatch between expected buffer size and actual access pattern.

The fix was committed as `f8cca819a4fb42aafa5f70df43c45e8c416d716f` on January 2, 2019.

## Recommendations

- **Suggested CWEs**: [CWE-125, CWE-122, CWE-787]
- **Vulnerability Name**: Heap buffer over-read in put_pixel_rows with quantized CMYK/RGB565
- **Origin**: 1-day (CVE-2018-19664)
- **Release Date**: 11/29/2018