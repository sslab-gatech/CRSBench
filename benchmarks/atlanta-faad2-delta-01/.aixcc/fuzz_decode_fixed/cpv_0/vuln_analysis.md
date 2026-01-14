# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: fuzz_decode_fixed
- **Vulnerability Type**: Signed integer overflow (manifestation of incorrect coefficient table selection)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: 
  - https://github.com/knik0/faad2/pull/185 (Fix merged November 6, 2023)
  - Commit: a2df562d63eff10f86480e0449242cbc9601b141

## Crash Log Analysis
- **Error Type**: UndefinedBehaviorSanitizer: signed integer overflow
- **Sanitizer**: undefined
- **Operation**: Addition overflow: `232566383 + 2055740917` cannot be represented in type `real_t` (aka `int`)
- **Crash Location**: libfaad/sbr_dct.c:816:17
- **Vulnerable Function**: DST4_32
- **DEDUP Token**: DST4_32--sbr_qmf_synthesis_32--sbrDecodeCoupleFrame

### Stack Trace
```
libfaad/sbr_dct.c:816:17: runtime error: signed integer overflow: 232566383 + 2055740917 cannot be represented in type 'real_t' (aka 'int')
    #0 DST4_32 (/out/fuzz_decode_fixed+0x1c6cc5)
    #1 sbr_qmf_synthesis_32 (/out/fuzz_decode_fixed+0x1c035d)
    #2 sbrDecodeCoupleFrame (/out/fuzz_decode_fixed+0x1adf78)
    #3 reconstruct_channel_pair (/out/fuzz_decode_fixed+0x1d4e80)
    #4 decode_cpe syntax.c
    #5 raw_data_block (/out/fuzz_decode_fixed+0x1ca575)
    #6 aac_frame_decode decoder.c
    #7 LLVMFuzzerTestOneInput (/out/fuzz_decode_fixed+0x19e4de)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: libfaad/tns.c
- **Function**: tns_decode_coef
- **Line Range**: 199-199
- **Column Range**: 5-70

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: libfaad/sbr_dct.c
- **Function**: DST4_32
- **Line Range**: 816-816
- **Column Range**: 5-26

### Root Cause Code Context
```c
static uint8_t tns_decode_coef(uint8_t order, uint8_t coef_res_bits, uint8_t coef_compress,
                            uint8_t *coef, real_t *a)
{
    uint8_t i, m;
    real_t tmp2[TNS_MAX_ORDER+1], b[TNS_MAX_ORDER+1];
    uint8_t table_index = 2 * (coef_compress == 0) + (coef_res_bits == 3);  // BUG: incorrect logic
    real_t* tns_coef = all_tns_coefs[table_index];
    uint8_t exp = 0;

    /* Conversion to signed integer */
    for (i = 0; i < order; i++)
        tmp2[i] = tns_coef[coef[i]];
    // ... rest of function
}
```

The bug is in the table_index calculation:
- **Buggy**: `table_index = 2 * (coef_compress == 0) + (coef_res_bits == 3);`
- **Fixed**: `table_index = 2 * (coef_compress != 0) + (coef_res_bits != 3);`

### Crash Site Code Context
```c
void DST4_32(real_t *y, real_t *x)
{
    // ... many local variable declarations (f0-f300+) ...
    
    f272 = f233 + f237;
    f274 = f235 - f239;
    // ...
    f288 = f272 - f274;
    f289 = f272 + f274;  // Line 816: INTEGER OVERFLOW HERE
    // ...
}
```

Where `real_t` is `int32_t` in fixed-point mode (fuzz_decode_fixed).

## CWE Classification
- **CWE-682**: Incorrect Calculation (primary)
- **CWE-190**: Integer Overflow or Wraparound (manifestation)
- **CWE-1325**: Improperly Controlled Sequential Memory Allocation (indirect - wrong table selection)

## Vulnerability Description

This vulnerability arises from an incorrect boolean logic condition in the `tns_decode_coef` function that calculates the TNS (Temporal Noise Shaping) coefficient table index. 

**Root Cause Analysis:**

The bug is in line 199 of `libfaad/tns.c`:
```c
uint8_t table_index = 2 * (coef_compress == 0) + (coef_res_bits == 3);
```

This incorrectly uses equality checks (`==`) when it should use inequality checks (`!=`). The correct logic should be:
```c
uint8_t table_index = 2 * (coef_compress != 0) + (coef_res_bits != 3);
```

The `all_tns_coefs` array contains 4 coefficient tables:
- Index 0: tns_coef_0_3 (coef_compress=0, coef_res_bits≠3)
- Index 1: tns_coef_0_4 (coef_compress=0, coef_res_bits=3)
- Index 2: tns_coef_1_3 (coef_compress≠0, coef_res_bits≠3)
- Index 3: tns_coef_1_4 (coef_compress≠0, coef_res_bits=3)

When the table_index is calculated incorrectly, the wrong coefficient table is selected. These incorrect coefficients propagate through the TNS decoding process and eventually reach the SBR (Spectral Band Replication) synthesis stage.

**Crash Manifestation:**

In fixed-point arithmetic mode (where `real_t` is `int32_t`), the incorrect TNS coefficients lead to accumulated errors in the audio processing pipeline. When these values reach the `DST4_32` function (Discrete Sine Transform type 4 for 32-point transform) in `libfaad/sbr_dct.c`, the mathematical operations on these corrupted values cause a signed integer overflow at line 816:
```c
f289 = f272 + f274;  // 232566383 + 2055740917 overflows int32_t
```

The maximum value for `int32_t` is 2,147,483,647, but this addition attempts to compute 2,288,307,300, causing undefined behavior.

**Impact:**

- In fixed-point builds, this causes integer overflow with undefined behavior
- May lead to incorrect audio output, crashes, or potential security issues depending on how the overflow is handled
- The bug affects AAC audio decoding with TNS enabled

## POV Analysis

The POV file (pov_0.blob, 106 bytes) is a crafted AAC audio stream designed to trigger the vulnerability. From the crash log output, we can see:
```
order: 6, coef_compress: 0, coef_res_bits: 3, table_index: 3
order: 7, coef_compress: 1, coef_res_bits: 4, table_index: 0
order: 7, coef_compress: 1, coef_res_bits: 4, table_index: 0
```

The POV carefully crafts TNS parameters that, when processed with the incorrect table_index calculation, select wrong coefficient tables leading to values that eventually overflow during DST4_32 computation.

## Patch Analysis

The patch (patch_0.diff) makes a simple but critical fix to the boolean logic in `libfaad/tns.c`:

```diff
-    uint8_t table_index = 2 * (coef_compress == 0) + (coef_res_bits == 3);
+    uint8_t table_index = 2 * (coef_compress != 0) + (coef_res_bits != 3);
```

This fix was developed by Steveice10 and merged in GitHub PR #185 on November 6, 2023 (commit a2df562d63eff10f86480e0449242cbc9601b141). The maintainer noted this type of regression could be prevented with more comprehensive roundtrip testing.

The fix ensures the correct TNS coefficient table is selected based on the `coef_compress` and `coef_res_bits` parameters, preventing the propagation of incorrect values through the audio processing pipeline.

## Recommendations
- **Suggested CWEs**: [CWE-682, CWE-190, CWE-1325]
- **Vulnerability Name**: Incorrect TNS Coefficient Table Selection Leading to Integer Overflow
- **Severity**: Medium to High (causes undefined behavior, potential for security impact in fixed-point builds)
- **Fix Verification**: The patch correctly implements the boolean logic for table selection
- **Testing**: Comprehensive roundtrip testing should be added to prevent similar regressions