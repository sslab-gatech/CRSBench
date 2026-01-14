# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: pcre2_fuzzer
- **Vulnerability Type**: Signed Integer Overflow
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: UndefinedBehaviorSanitizer: signed integer overflow
- **Crash Location**: src/pcre2_compile.c:9683:15
- **Vulnerable Function**: get_branchlength
- **DEDUP Token**: get_branchlength--set_lookbehind_lengths--check_lookbehinds
- **Error Details**: `signed integer overflow: 2147483647 - -1369814186 cannot be represented in type 'int'`

### Stack Trace
```
#0 get_branchlength /src/pcre2/src/pcre2_compile.c:9683:15
#1 set_lookbehind_lengths /src/pcre2/src/pcre2_compile.c:9758:18
#2 check_lookbehinds /src/pcre2/src/pcre2_compile.c:9958:10
#3 pcre2_compile_8 /src/pcre2/src/pcre2_compile.c:10414:15
#4 LLVMFuzzerTestOneInput /src/pcre2/src/pcre2_fuzzsupport.c:144:10
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/pcre2_compile.c
- **Function**: get_branchlength
- **Line Range**: 9657-9657
- **Column Range**: 1-40

### Location 2 (crash_site)  
- **Type**: crash_site
- **File Path**: src/pcre2_compile.c
- **Function**: get_branchlength
- **Line Range**: 9683-9683
- **Column Range**: 1-45

### Code Context

**Root Cause (Line 9657 - Incorrect overflow check):**
```c
if (lastitemlength != 0 &&  /* Should not occur, but just in case */
    min != 0 &&
    INT_MAX/lastitemlength < min - 1)  // BUG: Should check 'max' not 'min'
  {
  *errcodeptr = ERR87;  /* Integer overflow; lookbehind too big */
  return -1;
  }
```

**Crash Site (Line 9683 - Integer overflow occurs):**
```c
if (INT_MAX - branchlength < (int)itemlength ||
    (branchlength += itemlength) > LOOKBEHIND_MAX)
  {
  *errcodeptr = ERR87;
  return -1;
  }
```

The bug is at line 9657 where the code checks `min - 1` instead of `max - 1` when validating for integer overflow. This allows `itemlength` to be computed as `(max - 1) * lastitemlength` at line 9665 without proper overflow protection. Later, at line 9683, when adding `itemlength` to `branchlength`, a signed integer overflow occurs.

## CWE Classification
- **CWE-190**: Integer Overflow or Wraparound - The primary issue where the calculation `2147483647 - (-1369814186)` causes signed integer overflow
- **CWE-682**: Incorrect Calculation - The root cause is using the wrong variable (`min` instead of `max`) in the overflow check

## Vulnerability Description

This vulnerability is a signed integer overflow in the `get_branchlength()` function of PCRE2's pattern compilation code. The function calculates the length of lookbehind assertions in regular expressions.

**Root Cause:**
At line 9657, the code performs an overflow check before computing `itemlength = (max - 1) * lastitemlength`:
```c
INT_MAX/lastitemlength < min - 1  // BUG: checks 'min' instead of 'max'
```

This should be checking `max - 1` instead of `min - 1`, since the subsequent calculation at line 9665 uses `max`:
```c
itemlength = (max - 1) * lastitemlength;
```

**Exploitation:**
A specially crafted regex pattern with a lookbehind assertion containing large quantifiers can bypass the incorrect overflow check. When the minimum quantifier is small (or zero) but the maximum is very large, the check at line 9657 passes incorrectly. This allows a massive value to be computed and stored in `itemlength`.

Later, at line 9683, when the code attempts `branchlength += itemlength`, it performs the arithmetic `INT_MAX - branchlength < (int)itemlength`. With `branchlength` close to `INT_MAX` and a large (potentially negative when cast) `itemlength`, the subtraction `INT_MAX - branchlength` can overflow, triggering undefined behavior.

**Impact:**
- Undefined behavior due to signed integer overflow
- Potential for incorrect program behavior during regex compilation
- Could lead to incorrect lookbehind length calculations
- May cause denial of service if exploited during pattern compilation

## POV Analysis

The proof-of-vulnerability is a specially crafted regex pattern:
```
(?<!( {65054}){9,44965})
```

**Pattern Breakdown:**
- `(?<!...)` - Negative lookbehind assertion
- `( {65054})` - Group matching exactly 65054 spaces
- `{9,44965}` - Quantifier: minimum 9 repetitions, maximum 44965 repetitions

**Trigger Mechanism:**
1. The inner group `( {65054})` has `lastitemlength = 65054`
2. The quantifier `{9,44965}` sets `min = 9` and `max = 44965`
3. The incorrect overflow check tests: `INT_MAX/65054 < 9 - 1` → `33016 < 8` → **false** (check passes incorrectly)
4. The correct check should test: `INT_MAX/65054 < 44965 - 1` → `33016 < 44964` → **true** (would catch the overflow)
5. Because the check fails, `itemlength = (44965 - 1) * 65054 = 2,923,966,556` (overflows when added to branchlength)
6. At line 9683, the arithmetic triggers signed integer overflow

## Patch Analysis

**Patch Location:** src/pcre2_compile.c, line 9657

**Change Made:**
```diff
- INT_MAX/lastitemlength < min - 1)
+ INT_MAX/lastitemlength < max - 1)
```

**Fix Explanation:**
The patch corrects the overflow check to use the `max` variable instead of `min`. This ensures the overflow validation matches the actual calculation that follows at line 9665, where `itemlength = (max - 1) * lastitemlength` is computed.

With the fix:
- The check now properly validates: `INT_MAX/65054 < 44965 - 1` → `33016 < 44964` → **true**
- The overflow is detected before the problematic calculation
- The function returns with error code ERR87 ("Integer overflow; lookbehind too big")
- No undefined behavior occurs

## Recommendations
- **Suggested CWEs**: [CWE-190, CWE-682]
- **Vulnerability Name**: PCRE2 Lookbehind Integer Overflow Due to Incorrect Overflow Check
- **Severity**: Medium - Causes undefined behavior during pattern compilation but requires crafted regex input

---

**Analysis Complete**: This is a synthetic vulnerability involving an incorrect variable used in an integer overflow check, allowing signed integer overflow during lookbehind length calculation in PCRE2 regex compilation.