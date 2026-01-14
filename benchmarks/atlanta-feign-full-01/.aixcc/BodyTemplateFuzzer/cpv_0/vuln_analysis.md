# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: BodyTemplateFuzzer
- **Vulnerability Type**: Stack Overflow (ReDoS - Regular Expression Denial of Service)
- **Origin**: 1-day
- **Release Date**: 09/05/2023
- **References**: https://github.com/OpenFeign/feign/pull/2150

## Crash Log Analysis
- **Error Type**: java.lang.StackOverflowError
- **Crash Location**: Java standard library regex matching (java.util.regex.Pattern)
- **Root Cause Location**: core/src/main/java/feign/template/Expressions.java:63-75
- **DEDUP Token**: 0a7e7ae7e8b5de5d
- **Jazzer Error**: `com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)`

### Stack Trace
The crash occurs during regex pattern matching in the Java standard library:
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)
	at java.base/java.util.regex.Pattern$GroupTail.match(Pattern.java:4820)
Caused by: java.lang.StackOverflowError
	at java.base/java.util.regex.Pattern$Ques.match(Pattern.java:4230)
	at java.base/java.util.regex.Pattern$GroupHead.match(Pattern.java:4789)
	at java.base/java.util.regex.Pattern$Loop.match(Pattern.java:4898)
	at java.base/java.util.regex.Pattern$GroupTail.match(Pattern.java:4820)
	[repeating pattern continues...]
```

The stack trace shows recursive calls in the Java regex engine's pattern matching implementation, specifically in `GroupTail.match`, `Loop.match`, `Ques.match`, and `GroupHead.match` methods. This recursive behavior is triggered by the complex regex patterns used in OpenFeign's expression parsing.

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: core/src/main/java/feign/template/Expressions.java
- **Function**: create
- **Line Range**: 63-75
- **Column Range**: 1-80

The vulnerability exists in the `create` method where expressions are matched against complex regex patterns without any length validation.

### Code Context
```java
public static Expression create(final String value) {

  /* remove the start and end braces */
  final String expression = stripBraces(value);
  if (expression == null || expression.isEmpty()) {
    throw new IllegalArgumentException("an expression is required.");
  }

  /* create a new regular expression matcher for the expression */
  String variableName = null;
  String variablePattern = null;
  String operator = null;
  Matcher matcher = EXPRESSION_PATTERN.matcher(value);  // Line 75 - vulnerable call
  if (matcher.matches()) {
    /* grab the operator */
    operator = matcher.group(2).trim();
    ...
```

The problematic regex patterns are defined as:
```java
static final Pattern EXPRESSION_PATTERN =
    Pattern.compile("^(\\{([+#./;?&=,!@|]?)(.+)\\})$");  // Line 43-44

private static final Pattern VARIABLE_LIST_PATTERN = Pattern.compile(
    "(([\\w-\\[\\]$]|%[0-9A-Fa-f]{2})(\\.?([\\w-\\[\\]$]|%[0-9A-Fa-f]{2}))*(:.*|\\*)?)(,(([\\w-\\[\\]$]|%[0-9A-Fa-f]{2})(\\.?([\\w-\\[\\]$]|%[0-9A-Fa-f]{2}))*(:.*|\\*)?))*");  // Line 60-61
```

## CWE Classification
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS)
- **CWE-674**: Uncontrolled Recursion

## Vulnerability Description

This is a **Regular Expression Denial of Service (ReDoS)** vulnerability that manifests as a stack overflow. The vulnerability exists in OpenFeign's URI template expression parsing functionality in the `Expressions.java` file.

### Root Cause
The `EXPRESSION_PATTERN` and `VARIABLE_LIST_PATTERN` regex patterns contain complex structures with repetitive alternative paths (e.g., `(a|b)*`) and nested quantifiers. When these patterns are applied to very long input strings (especially crafted malicious inputs), the Java regex engine's backtracking algorithm can consume excessive stack space, leading to a `StackOverflowError`.

### Attack Vector
An attacker can provide a maliciously crafted expression template consisting of:
1. An opening brace `{` 
2. Followed by a very long string of repeated characters (e.g., thousands of 'a' characters)
3. This input causes the regex engine to enter deep recursion during pattern matching

### Impact
- **Denial of Service**: The application crashes with a StackOverflowError
- **Service Unavailability**: Any service using OpenFeign's template parsing becomes unavailable when processing malicious templates
- **Resource Exhaustion**: The attack consumes all available stack space before the JVM can detect and prevent the issue

### Discovery
This vulnerability was discovered through **OSS-Fuzz**, Google's continuous fuzzing service for open-source projects, as referenced in google/oss-fuzz#10684.

## POV Analysis

The proof-of-vulnerability (pov_0.blob) is a 65,539-byte file containing:
- An opening brace `{` character (0x7b)
- Followed by approximately 65,538 'a' characters (0x61)

This input is specifically crafted to trigger the worst-case behavior of the regex patterns:
1. The opening `{` matches the start of the `EXPRESSION_PATTERN`
2. The very long string of 'a' characters causes the regex engine to explore numerous backtracking paths
3. The recursive pattern matching exhausts the JVM stack space before completing
4. This results in a `StackOverflowError` at line 4820 in `Pattern$GroupTail.match()`

## Patch Analysis

The vulnerability was fixed in **Pull Request #2150** merged on August 8, 2023, and released in **OpenFeign version 12.5** on September 5, 2023.

### Fix Implementation
The patch introduces a **maximum length check** for expression strings before attempting regex matching:

```diff
+  private static final int MAX_EXPRESSION_LENGTH = 10000;
+
...
+    if (expression.length() > MAX_EXPRESSION_LENGTH) {
+      throw new IllegalArgumentException(
+          "expression is too long. Max length: " + MAX_EXPRESSION_LENGTH);
+    }
+
     /* create a new regular expression matcher for the expression */
```

### Fix Location
- **File**: core/src/main/java/feign/template/Expressions.java
- **Lines Added**: 9-10 (constant definition), 71-75 (validation check)
- **Approach**: Input validation - reject expressions longer than 10,000 characters before regex matching

### Rationale
Rather than redesigning the complex regex patterns themselves (which could break existing functionality), the fix adds a pragmatic length limit that:
1. Prevents the stack overflow by rejecting excessively long inputs
2. Still allows legitimate use cases (10,000 character limit is reasonable for URI templates)
3. Provides a clear error message to users when the limit is exceeded
4. Maintains backward compatibility for normal usage

### Security Properties
The fix transforms a crash vulnerability into a controlled error condition:
- **Before**: Long input → Stack overflow → Application crash
- **After**: Long input → IllegalArgumentException → Graceful error handling

## Recommendations
- **Suggested CWEs**: [CWE-400, CWE-1333, CWE-674]
- **Vulnerability Name**: ReDoS via Regex Stack Overflow in Expression Parsing
- **Severity**: Medium (DoS impact, but requires crafted input)
- **Affected Component**: core/src/main/java/feign/template/Expressions.java
- **Fix Version**: OpenFeign 12.5 (released September 5, 2023)