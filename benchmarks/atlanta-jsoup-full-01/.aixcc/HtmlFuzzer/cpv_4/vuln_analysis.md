# Vulnerability Analysis for cpv_4

## Summary
- **CPV ID**: cpv_4
- **Harness**: HtmlFuzzer
- **Vulnerability Type**: Stack Overflow / Regular Expression Denial of Service (ReDoS)
- **Origin**: 1-day
- **Release Date**: 08/18/2021
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-37714
  - https://github.com/jhy/jsoup/security/advisories/GHSA-m72m-mhq2-9p6c

## Crash Log Analysis
- **Error Type**: Stack Overflow (FuzzerSecurityIssueLow)
- **Crash Location**: Java regex engine - java.util.regex.Pattern$Curly.match0 and related methods
- **Vulnerable Function**: The crash occurs in the Java regex engine when processing the vulnerable pattern in org.jsoup.internal.StringUtil
- **DEDUP Token**: e5b4d9089e43f612

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)
	at java.base/java.util.regex.Pattern$Curly.match0(Pattern.java:4402)
	at java.base/java.util.regex.Pattern$Curly.match(Pattern.java:4364)
	at java.base/java.util.regex.Pattern$GroupHead.match(Pattern.java:4789)
	at java.base/java.util.regex.Pattern$Loop.match(Pattern.java:4898)
	at java.base/java.util.regex.Pattern$GroupTail.match(Pattern.java:4820)
	at java.base/java.util.regex.Pattern$BmpCharProperty.match(Pattern.java:3955)
Caused by: java.lang.StackOverflowError
	at java.base/java.lang.StringUTF16.checkIndex(StringUTF16.java:1624)
	at java.base/java.lang.StringUTF16.charAt(StringUTF16.java:1421)
	at java.base/java.lang.String.charAt(String.java:1514)
	at java.base/java.util.regex.Pattern$BmpCharProperty.match(Pattern.java:3954)
	at java.base/java.util.regex.Pattern$Curly.match0(Pattern.java:4380)
	[... pattern repeats, indicating catastrophic backtracking ...]
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/main/java/org/jsoup/internal/StringUtil.java
- **Function**: resolve (via extraDotSegmentsPattern)
- **Line Range**: 284-284
- **Column Range**: 47-80

### Code Context
```java
// Line 284 - VULNERABLE PATTERN
private static final Pattern extraDotSegmentsPattern = Pattern.compile("^/((\\.{1,2}/)+)");

// Line 292-298 - Usage context
public static URL resolve(URL base, String relUrl) throws MalformedURLException {
    // workaround: java resolves '//path/file + ?foo' to '//path/?foo', not '//path/file?foo' as desired
    if (relUrl.startsWith("?"))
        relUrl = base.getPath() + relUrl;
    // workaround: //example.com + ./foo = //example.com/./foo, not //example.com/foo
    URL url = new URL(base, relUrl);
    String fixedFile = extraDotSegmentsPattern.matcher(url.getFile()).replaceFirst("/");
    if (url.getRef() != null) {
        fixedFile = fixedFile + "#" + url.getRef();
    }
    return new URL(url.getProtocol(), url.getHost(), url.getPort(), fixedFile);
}
```

**FIXED PATTERN (line 284):**
```java
private static final Pattern extraDotSegmentsPattern = Pattern.compile("^/(?>(?>\\.\\.?/)+)");
```

## CWE Classification
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS)
- **CWE-835**: Loop with Unreachable Exit Condition ('Infinite Loop')
- **CWE-400**: Uncontrolled Resource Consumption

## Vulnerability Description

This vulnerability is a **Regular Expression Denial of Service (ReDoS)** caused by catastrophic backtracking in the regex pattern used to normalize URL paths in jsoup's `StringUtil.resolve()` method.

### Root Cause

The vulnerable regex pattern `^/((\\.{1,2}/)+)` contains nested quantifiers with a capturing group:
- The outer `()+` creates a capturing group that can repeat
- The inner `\\.{1,2}` matches 1 or 2 dots
- When given input like `/../` repeated many times, the regex engine explores exponential backtracking paths

### Attack Vector

An attacker can craft malicious HTML/XML input containing a `<base>` tag with an `href` attribute containing a long sequence of `/../` segments, such as:
```html
<base href="http:/../././../././../[...many repetitions...]">
```

When jsoup parses this input and attempts to resolve the URL, the regex engine enters catastrophic backtracking, consuming excessive CPU and stack space, eventually leading to:
1. Stack overflow error
2. Thread timeout
3. Application hang/freeze

### Impact

- **Denial of Service**: An attacker can cause the parser to hang indefinitely or consume excessive resources
- **Application Availability**: Services processing untrusted HTML/XML input become vulnerable to resource exhaustion
- **Stack Exhaustion**: The recursive regex matching fills up the call stack

### Fix Analysis

The patch replaces the vulnerable capturing groups with **atomic groups** (using `(?>...)` syntax):
```
Before: ^/((\\.{1,2}/)+)
After:  ^/(?>(?>\\.\\.?/)+)
```

Atomic groups prevent backtracking once matched, eliminating the exponential complexity. The regex engine commits to matches within atomic groups and never reconsiders them, preventing catastrophic backtracking.

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted `<base>` element with an extremely long sequence of `/../` path segments:

```html
<base/Href=http:/../././../././../[...1000+ repetitions...]>
```

This input specifically targets the `extraDotSegmentsPattern` regex:
1. jsoup parses the HTML and encounters the `<base>` element
2. The parser attempts to resolve the relative URL
3. `StringUtil.resolve()` is called with the malicious URL
4. The vulnerable regex pattern `^/((\\.{1,2}/)+)` is applied
5. Catastrophic backtracking occurs due to the nested quantifiers
6. Stack overflow results from deep recursion in the regex engine

The POV demonstrates that the vulnerability can be triggered with realistic HTML parsing scenarios, making it practical for attackers to exploit.

## Patch Analysis

**File**: `src/main/java/org/jsoup/internal/StringUtil.java`

**Change** (line 284):
```diff
-    private static final Pattern extraDotSegmentsPattern = Pattern.compile("^/((\\.{1,2}/)+)");
+    private static final Pattern extraDotSegmentsPattern = Pattern.compile("^/(?>(?>\\.\\.?/)+)");
```

### What Changed:
1. **Removed capturing groups** `((...))` - not needed for the `replaceFirst("/")` operation
2. **Added atomic groups** `(?>(?>...)+)` - prevents backtracking
3. **Simplified inner pattern** `\\.{1,2}` became `\\.\\.?` (equivalent but clearer with atomic groups)

### Why It Works:
- **Atomic groups commit to matches**: Once `(?>\\.\\.?/)` matches, it never backtracks
- **Linear complexity**: The outer `(?>...)+` also prevents backtracking between repetitions
- **Same functionality**: The pattern still matches and removes leading `/./` and `/../` sequences
- **Performance**: Matching time is now linear O(n) instead of exponential O(2^n)

## Recommendations
- **Suggested CWEs**: [CWE-1333, CWE-835, CWE-400]
- **Vulnerability name**: "Regular Expression Denial of Service (ReDoS) in jsoup URL Resolution"
- **Severity**: High (CVSS 7.5) - Network-accessible DoS with no authentication required
- **Affected versions**: jsoup < 1.14.2
- **Fixed version**: jsoup 1.14.2 (released 2021-08-15)