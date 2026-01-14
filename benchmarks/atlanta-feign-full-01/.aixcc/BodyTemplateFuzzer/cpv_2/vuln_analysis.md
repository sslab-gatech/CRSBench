# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: BodyTemplateFuzzer
- **Vulnerability Type**: Regular Expression Injection
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Regular Expression Injection
- **Crash Location**: feign/template/Expression.java:35
- **Vulnerable Function**: `Expression` constructor / `Pattern.compile()`
- **DEDUP Token**: c01aa23ef05bf739

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Regular Expression Injection
Regular expression patterns that contain unescaped untrusted input can consume
arbitrary amounts of CPU time. To properly escape the input, wrap it with
Pattern.quote(...).
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.hookInternal(RegexInjection.kt:164)
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.patternHook(RegexInjection.kt:85)
	at feign.template.Expression.lambda$new$0(Expression.java:35)
	at java.base/java.util.Optional.ifPresent(Optional.java:178)
	at feign.template.Expression.<init>(Expression.java:35)
	at feign.template.Expressions$SimpleExpression.<init>(Expressions.java:128)
	at feign.template.Expressions.create(Expressions.java:103)
	at feign.template.Template.parseFragment(Template.java:218)
	at feign.template.Template.parseTemplate(Template.java:202)
	at feign.template.Template.<init>(Template.java:61)
	at feign.template.BodyTemplate.<init>(BodyTemplate.java:54)
	at feign.template.BodyTemplate.create(BodyTemplate.java:39)
	at BodyTemplateFuzzer.fuzzerTestOneInput(BodyTemplateFuzzer.java:26)
Caused by: java.util.regex.PatternSyntaxException: Illegal repetition near index 1
{str2
 ^
	at java.base/java.util.regex.Pattern.error(Pattern.java:2028)
	at java.base/java.util.regex.Pattern.closure(Pattern.java:3309)
	at java.base/java.util.regex.Pattern.sequence(Pattern.java:2214)
	at java.base/java.util.regex.Pattern.expr(Pattern.java:2069)
	at java.base/java.util.regex.Pattern.compile(Pattern.java:1783)
	at java.base/java.util.regex.Pattern.<init>(Pattern.java:1430)
	at java.base/java.util.regex.Pattern.compile(Pattern.java:1069)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: core/src/main/java/feign/template/Expression.java
- **Function**: `Expression` (constructor)
- **Line Range**: 35-35
- **Column Range**: 1-999

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: core/src/main/java/feign/template/Expressions.java
- **Function**: `create`
- **Line Range**: 82-87
- **Column Range**: 1-999

### Code Context

**Crash Site (Expression.java:35):**
```java
Expression(String name, String pattern) {
    this.name = name;
    Optional.ofNullable(pattern).ifPresent(s -> this.pattern = Pattern.compile(s));  // Line 35
}
```

The vulnerability occurs when `Pattern.compile()` is called with an unsanitized user-controlled pattern string.

**Root Cause (Expressions.java:82-87):**
```java
if (variableName.contains(":")) {
    /* split on the colon */
    String[] parts = variableName.split(":");
    variableName = parts[0];
    variablePattern = parts[1];  // Line 86 - unsanitized pattern passed directly
}
```

The code extracts a pattern from the expression string (e.g., `{str1:{str2:}}`) and passes it directly to the Expression constructor without sanitization. When the input contains regex metacharacters like `{`, it causes a `PatternSyntaxException`.

## CWE Classification
- **CWE-185**: Incorrect Regular Expression
- **CWE-400**: Uncontrolled Resource Consumption (related to potential ReDoS)
- **CWE-20**: Improper Input Validation

## Vulnerability Description

This vulnerability occurs in the Feign template expression parser when processing variable patterns. The code allows users to specify patterns in the format `{variable:pattern}`. However, the pattern portion is not sanitized before being passed to `Pattern.compile()`.

**Attack Vector:**
When a malicious input like `{str1:{str2:}}` is provided:
1. The parser extracts `{str2:` as the pattern for the outer variable
2. This pattern contains the regex metacharacter `{` which has special meaning
3. When `Pattern.compile("{str2:")` is called, it throws `PatternSyntaxException: Illegal repetition`
4. This can be detected by Jazzer's RegexInjection sanitizer as a security issue

**Impact:**
- **Denial of Service**: Malicious patterns could cause PatternSyntaxException or, with carefully crafted inputs, cause ReDoS (Regular Expression Denial of Service) by creating exponential-time regex matching
- **Application Crash**: Unhandled exceptions can crash the application
- **Resource Exhaustion**: Complex regex patterns can consume excessive CPU time

The vulnerability is triggered when untrusted user input is used in template expressions without proper validation or escaping.

## POV Analysis

**POV Input:** `{str1:{str2:}}`

This input demonstrates the vulnerability by:
1. Creating a nested template expression structure
2. The inner expression `{str2:}` is interpreted as having an empty pattern after the colon
3. When the parser processes the outer variable, it extracts `{str2:` as the pattern (everything after the first colon)
4. The unescaped `{` character is a regex metacharacter for repetition quantifiers
5. `Pattern.compile("{str2:")` fails with "Illegal repetition" because `{` expects a numeric quantifier but finds `s` instead

This is a minimal test case that triggers the regex injection detection.

## Patch Analysis

**Patch File:** patch_0.diff

The patch adds proper sanitization using `Pattern.quote()`:

```diff
@@ -83,7 +83,12 @@ public final class Expressions {
         /* split on the colon */
         String[] parts = variableName.split(":");
         variableName = parts[0];
-        variablePattern = parts[1];
+        String rawPattern = parts[1];
+        if (rawPattern.isEmpty()) {
+          variablePattern = null;
+        } else {
+          variablePattern = Pattern.quote(rawPattern);
+        }
       }
```

**Fix Analysis:**
1. **Pattern.quote() wrapper**: The patch wraps the user-provided pattern with `Pattern.quote()`, which escapes all regex metacharacters. This converts the pattern into a literal string match rather than a regex.
2. **Empty pattern handling**: If the pattern is empty (e.g., `{variable:}`), it sets `variablePattern` to `null` instead of passing an empty string to Pattern.compile()
3. **Location**: The fix is applied at the root cause location in `Expressions.java` where the pattern is extracted, preventing malicious patterns from ever reaching `Pattern.compile()`

**Security Impact:**
This fix completely mitigates the regex injection vulnerability by ensuring that all user-provided patterns are treated as literal strings rather than regex patterns. This prevents both PatternSyntaxException errors and potential ReDoS attacks.

## Origin Classification Reasoning

This vulnerability is classified as **synthetic** because:

1. **No official CVE or security advisory found**: Extensive web searches did not reveal any CVE, OSV, GHSA, or official security advisory for this specific vulnerability
2. **No matching GitHub issue**: While similar issues exist (#1464, #1512, #1231), they describe related but different problems (JSON header truncation, header value parsing)
3. **No matching commit**: The GitHub commit history for Expressions.java does not show a commit specifically adding Pattern.quote() for regex injection mitigation in the exact location shown in the patch
4. **Different fix approach**: Real-world fixes in the Feign repository (like #1776) took different approaches focused on expression validation rather than Pattern.quote() sanitization
5. **Synthetic nature of the POV**: The test input `{str1:{str2:}}` appears to be a crafted fuzzing input rather than a real-world exploit

While the vulnerability pattern (regex injection via unsanitized Pattern.compile()) is well-documented in security literature (CERT IDS08-J, CWE-185), this specific instance in Feign does not have a published 1-day reference.

## Recommendations

### Suggested CWEs
- **Primary**: CWE-185 (Incorrect Regular Expression)
- **Secondary**: CWE-400 (Uncontrolled Resource Consumption)
- **Tertiary**: CWE-20 (Improper Input Validation)

### Vulnerability Name
"Regex Injection in Feign Template Expression Pattern Parsing"

### Additional Security Considerations
1. Input validation should be performed before pattern extraction
2. Consider limiting the complexity of allowed patterns to prevent ReDoS
3. Add unit tests with malicious regex patterns to prevent regression
4. Consider using a safer pattern matching approach that doesn't require regex compilation for user-provided patterns