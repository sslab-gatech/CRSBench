# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ServicesUtilsFuzzer
- **Vulnerability Type**: Regular Expression Denial of Service (ReDoS) / Stack Overflow
- **Origin**: 1-day
- **Release Date**: 11/25/2024
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2024-10270
  - https://github.com/advisories/GHSA-wq8x-cg39-8mrr

## Crash Log Analysis
- **Error Type**: java.lang.StackOverflowError
- **Exception**: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow
- **Crash Location**: java.base/java.util.regex.Pattern (multiple match functions in infinite recursion)
- **Vulnerable Function**: SearchQueryUtils.getFields()
- **DEDUP Token**: 134db8e198ead238

### Stack Trace
The stack trace shows catastrophic backtracking in the Java regex engine, causing infinite recursion through Pattern matching methods:

```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)
        at java.base/java.util.regex.Pattern$GroupTail.match(Pattern.java:4820)
        at java.base/java.util.regex.Pattern$Ques.match(Pattern.java:4229)
        at java.base/java.util.regex.Pattern$GroupHead.match(Pattern.java:4789)
        at java.base/java.util.regex.Pattern$Loop.match(Pattern.java:4898)
Caused by: java.lang.StackOverflowError
        at java.base/java.util.regex.Pattern$CharProperty.match(Pattern.java:3927)
        at java.base/java.util.regex.Pattern$Ques.match(Pattern.java:4229)
        [... infinite recursion continues ...]
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: services/src/main/java/org/keycloak/utils/SearchQueryUtils.java
- **Function**: getFields
- **Line Range**: 29-29 (pattern definition)
- **Column Range**: 1-200+

### Code Context
The vulnerable code uses a complex regex pattern with nested quantifiers that causes catastrophic backtracking:

```java
public class SearchQueryUtils {
    public static final Pattern queryPattern = Pattern.compile("\\s*(?:(?<name>(?:(?:[^\":\\s]?)+)+)|\"(?<nameEsc>(?:(?:\\\\.|[^\\\\\"])?)+)\")\\s*:\\s*(?:(?<value>(?:(?:[^\"\\s]?)+)+)|\"(?<valueEsc>(?:(?:\\\\.|[^\\\\\"])?)+)\")\\s*");
    
    public static Map<String, String> getFields(final String query) {
        Matcher matcher = queryPattern.matcher(query);
        Map<String, String> ret = new HashMap<>();
        while (matcher.find()) {
            String name = matcher.group("name");
            if (name == null) {
                name = unescape(matcher.group("nameEsc"));
            }

            String value = matcher.group("value");
            if (value == null) {
                value = unescape(matcher.group("valueEsc"));
            }

            ret.put(name, value);
        }
        return ret;
    }
}
```

**Vulnerable Pattern Analysis:**
The pattern `(?:(?:[^\":\\s]?)+)+` contains nested quantifiers (`?` inside `+` inside `+`), which causes exponential time complexity during backtracking when matching fails. This is a classic ReDoS vulnerability pattern.

## CWE Classification
- **CWE-1333**: Inefficient Regular Expression Complexity (primary)
- **CWE-185**: Incorrect Regular Expression
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-674**: Uncontrolled Recursion

## Vulnerability Description

This is a **Regular Expression Denial of Service (ReDoS)** vulnerability in the Keycloak SearchQueryUtils class. The vulnerability exists in the `queryPattern` regex used to parse search queries.

**Root Cause:**
The regex pattern contains nested quantifiers `(?:(?:[^\":\\s]?)+)+` which creates exponential time complexity. When untrusted input is processed (like the POV input containing many backslashes and colons), the regex engine enters catastrophic backtracking, causing:
1. Exponential increase in matching attempts
2. Deep recursion in the regex matching algorithm
3. Stack overflow due to excessive recursion depth
4. Complete denial of service

**Attack Scenario:**
An attacker can send a specially crafted query string to any Keycloak endpoint that uses SearchQueryUtils.getFields(). The malicious input triggers the regex engine to enter catastrophic backtracking, exhausting CPU and stack resources, leading to denial of service.

**Impact:**
- **Availability**: HIGH - Complete denial of service, system becomes unresponsive
- **Confidentiality**: NONE
- **Integrity**: NONE
- **CVSS Score**: 6.5-7.1 (MEDIUM to HIGH severity)

## POV Analysis

The POV file contains a carefully crafted input designed to trigger catastrophic backtracking:

```
 \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\[... many backslashes ...]\\\\\\\\\\":"value
```

**Input Characteristics:**
- Starts with a space
- Contains approximately 1000+ consecutive backslashes
- Ends with a backslash-escaped quote and colon: `\\":"value`
- This specific pattern causes the regex engine to try numerous backtracking paths

**Why This Triggers the Vulnerability:**
The pattern `(?:(?:[^\":\\s]?)+)+` attempts to match the backslashes in multiple ways due to the nested quantifiers and the `?` making characters optional. When the match fails at the colon, the regex engine backtracks exponentially, trying every possible combination of matching the backslashes, leading to stack exhaustion.

## Patch Analysis

The patch (patch_0.diff) completely removes the vulnerable regex-based parsing and replaces it with a manual character-by-character parser:

**Key Changes:**
1. **Removed vulnerable regex patterns:**
   - `queryPattern` with nested quantifiers
   - `escapedCharsPattern`

2. **Replaced with iterative parsing:**
   - Manual character array traversal
   - Explicit quote and escape handling
   - Linear time complexity O(n) instead of exponential

3. **New implementation:**
   - Processes input character-by-character
   - Tracks quote state explicitly
   - Handles escaped characters without regex
   - No recursive backtracking possible

**Fix Effectiveness:**
The new implementation eliminates the ReDoS vulnerability entirely by:
- Removing all regex usage from the parsing logic
- Using a simple state machine approach
- Ensuring linear time complexity regardless of input
- Preventing stack overflow through iterative processing

**Test Case Added:**
The patch includes a regression test `testReDoS()` that verifies the fix by processing 50,000 iterations of the previously problematic input pattern, confirming it completes in reasonable time.

## Recommendations

**Suggested CWEs:** [CWE-1333, CWE-185, CWE-400, CWE-674]

**Vulnerability Name:** "Keycloak SearchQueryUtils Regular Expression Denial of Service (ReDoS)"

**Severity:** MEDIUM to HIGH (CVSS 6.5-7.1)

**Additional Notes:**
- This is CVE-2024-10270, affecting Keycloak versions 20.0.0 through 26.0.5
- Fixed in Keycloak versions 24.0.9 and 26.0.6+
- The vulnerability is exploitable remotely by authenticated users with low privileges
- No user interaction required for exploitation
- The fix demonstrates best practices for avoiding ReDoS: replacing complex regex with simple iterative parsing