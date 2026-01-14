# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: HtmlFuzzer
- **Vulnerability Type**: Stack Overflow (Uncontrolled Recursion)
- **Origin**: 1-day
- **Release Date**: 08/18/2021
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-37714
  - https://github.com/jhy/jsoup/security/advisories/GHSA-m72m-mhq2-9p6c

## Crash Log Analysis
- **Error Type**: java.lang.StackOverflowError (wrapped in FuzzerSecurityIssueLow)
- **Crash Location**: HtmlTreeBuilderState.java:1559 (InTemplate state, EOF case)
- **Vulnerable Functions**: 
  - `HtmlTreeBuilder.process()` (lines 167, 172)
  - `HtmlTreeBuilderState$18.process()` (line 1559 - InTemplate state)
  - `HtmlTreeBuilderState$7.process()` (line 311)
  - `HtmlTreeBuilder.resetInsertionMode()` (line 478)
- **DEDUP Token**: 318fef250fe29bbd

### Stack Trace
The crash shows an infinite recursion pattern:
```
java.lang.StackOverflowError
	at org.jsoup.parser.HtmlTreeBuilder.resetInsertionMode(HtmlTreeBuilder.java:478)
	at org.jsoup.parser.HtmlTreeBuilderState$18.process(HtmlTreeBuilderState.java:1555)
	at org.jsoup.parser.HtmlTreeBuilder.process(HtmlTreeBuilder.java:172)
	at org.jsoup.parser.HtmlTreeBuilderState$7.process(HtmlTreeBuilderState.java:311)
	at org.jsoup.parser.HtmlTreeBuilder.process(HtmlTreeBuilder.java:167)
	at org.jsoup.parser.HtmlTreeBuilderState$18.process(HtmlTreeBuilderState.java:1559)
	[pattern repeats indefinitely]
```

The recursion occurs when processing EOF tokens in deeply nested template elements, where:
1. InTemplate state's EOF handler calls `tb.process(t)` (line 1557)
2. This triggers state processing which may recurse back to InTemplate
3. Without a depth check, this creates unbounded recursion

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/main/java/org/jsoup/parser/HtmlTreeBuilderState.java
- **Function**: InTemplate.process() (anonymous inner class for InTemplate state)
- **Line Range**: 1556-1557
- **Column Range**: 1-40

### Location 2 (root_cause)
- **Type**: root_cause  
- **File Path**: src/main/java/org/jsoup/parser/HtmlTreeBuilderState.java
- **Function**: InTemplate.process() (anonymous inner class for InTemplate state, EOF case)
- **Line Range**: 1556-1557
- **Column Range**: 1-40

**Note**: The crash_site and root_cause are the same location in this case, as the missing recursion depth check at line 1556 is both where the error manifests and where the defect exists.

### Code Context (Before Fix)
```java
case EOF:
    if (!tb.onStack("template")) {// stop parsing
        return true;
    }
    tb.error(this);
    tb.popStackToClose("template");
    tb.clearFormattingElementsToLastMarker();
    tb.popTemplateMode();
    tb.resetInsertionMode();
    // spec deviation - if we did not break out of Template, stop processing, and don't worry about cleaning up ultra-deep template stacks
    // limited depth because this can recurse and will blow stack if too deep
    if (tb.state() != InTemplate)    // ← VULNERABLE: No depth check!
        return tb.process(t);
    else return true;
```

### Code Context (After Fix)
```java
if (tb.state() != InTemplate && tb.templateModeSize() < 12)  // ← FIXED: Added depth check
    return tb.process(t);
else return true;
```

## CWE Classification
- **CWE-674**: Uncontrolled Recursion
- **CWE-674** → **CWE-400**: Uncontrolled Resource Consumption (leads to DoS)
- **CWE-835**: Loop with Unreachable Exit Condition (Infinite Loop) - mentioned in CVE-2021-37714

## Vulnerability Description

This vulnerability is a **stack overflow caused by uncontrolled recursion** in jsoup's HTML template parsing logic.

### Root Cause
When processing EOF (end-of-file) tokens in the `InTemplate` state, the parser attempts to clean up the template mode stack by calling `resetInsertionMode()` and then recursively processing the token again. However, the original code only checked if the state changed away from `InTemplate`, without verifying the template stack depth.

With specially crafted HTML input containing deeply nested `<template>` tags, the parser enters an infinite recursion loop:
1. InTemplate EOF handler processes token
2. Calls `resetInsertionMode()` which may keep state as InTemplate
3. Recursively calls `tb.process(t)` to reprocess the EOF token
4. Returns to step 1, repeating indefinitely

### Attack Vector
An attacker can provide malicious HTML input with deeply nested template tags (e.g., `<template><template><template>...`) that triggers this recursion when the parser reaches EOF, causing:
- Stack overflow exception
- Denial of Service (application crash)
- Resource exhaustion

### Fix
The patch adds a recursion depth limit by checking `tb.templateModeSize() < 12`, ensuring that recursion stops after processing 12 template levels. This prevents stack overflow while still handling reasonably nested template structures.

## POV Analysis

The POV file (`pov_0.blob`, 90KB) contains a repeating pattern of nested template tags:
```html
t<template<temb.><t<template<temb.><t<template<temb.>...
```

This input creates deeply nested template elements that trigger the EOF handling logic repeatedly, causing the unbounded recursion that leads to stack overflow. The malformed but parseable HTML structure specifically targets the template state machine's recursion vulnerability.

## Patch Analysis

**File Modified**: `src/main/java/org/jsoup/parser/HtmlTreeBuilderState.java`

**Change**: Line 1556 (InTemplate state, EOF case)
```diff
- if (tb.state() != InTemplate)
+ if (tb.state() != InTemplate && tb.templateModeSize() < 12)
```

**Explanation**: 
- The patch adds a check `tb.templateModeSize() < 12` to limit recursion depth
- `templateModeSize()` returns the size of the template mode stack
- When template nesting exceeds 12 levels, recursion stops and returns `true`
- This prevents stack overflow while maintaining reasonable template parsing capability
- The limit of 12 is a pragmatic choice balancing functionality with safety

**Root Cause Location**: The patch location IS the root cause - the missing depth check at line 1556 allowed unbounded recursion.

## Vulnerability Origin and Reference

### Origin: 1-day

This is confirmed as a **1-day vulnerability** based on:

1. **CVE Assignment**: CVE-2021-37714
2. **GitHub Security Advisory**: GHSA-m72m-mhq2-9p6c  
3. **Fixed Version**: jsoup 1.14.2 (August 15, 2021)
4. **NVD Published Date**: August 18, 2021

### Evidence Matching Criteria

The vulnerability matches CVE-2021-37714 based on:
- **Function**: Exact match - InTemplate EOF handling with recursion
- **Bug Type**: Stack overflow from uncontrolled recursion - matches CVE description of "throw unexpected exception"
- **Fix**: The patch adding `templateModeSize() < 12` check is present in current jsoup codebase
- **File/Location**: HtmlTreeBuilderState.java InTemplate state - specific to template parsing
- **Timeline**: CVE-2021-37714 was published August 18, 2021, and fixed in jsoup 1.14.2 (August 15, 2021)

### Discovery
The vulnerability was discovered through OSS-Fuzz integration using the Jazzer JVM Fuzzer, with contributions from Roman Wagner at Code Intelligence.

## Recommendations

### Suggested CWEs
- **Primary**: CWE-674 (Uncontrolled Recursion)
- **Secondary**: CWE-400 (Uncontrolled Resource Consumption)
- **Related**: CWE-835 (Infinite Loop)

### Vulnerability Name
"jsoup Template Parsing Stack Overflow via Uncontrolled Recursion"

### Remediation
Upgrade to jsoup version 1.14.2 or later, which includes the recursion depth limit fix.

---

**Analysis completed**: This vulnerability analysis confirms cpv_2 as a real-world 1-day vulnerability (CVE-2021-37714) affecting jsoup's HTML template parser, fixed by adding a recursion depth check to prevent stack overflow in deeply nested template structures.