# Vulnerability Analysis for cpv_11

## Summary
- **CPV ID**: cpv_11
- **Harness**: JenkinsThreeFDP
- **Vulnerability Type**: Regular Expression Injection (ReDoS)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueLow: Regular Expression Injection
- **Crash Location**: `io/jenkins/plugins/toyplugin/AccessFilter.java:87`
- **Vulnerable Function**: `doGet`
- **DEDUP Token**: cc0343168b8888d0
- **Root Cause**: Caused by `java.util.regex.PatternSyntaxException: Dangling meta character '*' near index 3`

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Regular Expression Injection
Regular expression patterns that contain unescaped untrusted input can consume
arbitrary amounts of CPU time. To properly escape the input, wrap it with
Pattern.quote(...).
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.hookInternal(RegexInjection.kt:164)
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.patternHook(RegexInjection.kt:85)
	at io.jenkins.plugins.toyplugin.AccessFilter.doGet(AccessFilter.java:87)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.testAccessFilter(JenkinsThreeFDP.java:302)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzz(JenkinsThreeFDP.java:106)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzzerTestOneInput(JenkinsThreeFDP.java:79)
Caused by: java.util.regex.PatternSyntaxException: Dangling meta character '*' near index 3
.*(*).*
   ^
	at java.base/java.util.regex.Pattern.error(Pattern.java:2028)
	at java.base/java.util.regex.Pattern.sequence(Pattern.java:2203)
	at java.base/java.util.regex.Pattern.expr(Pattern.java:2069)
	at java.base/java.util.regex.Pattern.group0(Pattern.java:3050)
	at java.base/java.util.regex.Pattern.sequence(Pattern.java:2124)
	at java.base/java.util.regex.Pattern.expr(Pattern.java:2069)
	at java.base/java.util.regex.Pattern.compile(Pattern.java:1783)
	at java.base/java.util.regex.Pattern.<init>(Pattern.java:1430)
	at java.base/java.util.regex.Pattern.compile(Pattern.java:1069)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: `plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/AccessFilter.java`
- **Function**: `doGet`
- **Line Range**: 87-87
- **Column Range**: 1-60

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: `plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/AccessFilter.java`
- **Function**: `doGet`
- **Line Range**: 79-79
- **Column Range**: 1-60

### Code Context

**Crash Site (Line 87):**
```java
Pattern pattern = Pattern.compile(".*(" + ip + ").*");
```

**Root Cause (Line 79):**
```java
if (admin || request.hasParameter("skip")) {
    skip = Boolean.parseBoolean(request.getParameter("skip"));
}
```

The vulnerability has two components:
1. **Authorization Bypass (Line 79)**: The logic uses `||` (OR) instead of `&&` (AND), allowing non-admin users to bypass IP validation by simply providing a "skip" parameter
2. **Regex Injection (Line 87)**: Unsanitized user input (`ip` parameter) is directly concatenated into a regex pattern, allowing injection of malicious regex metacharacters

## CWE Classification
- **CWE-185**: Incorrect Regular Expression
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS)
- **CWE-862**: Missing Authorization (for the skip bypass)

## Vulnerability Description

This vulnerability consists of two related security issues in the `AccessFilter.doGet()` method:

### 1. Authorization Bypass
The code at line 79 uses an OR condition (`admin || request.hasParameter("skip")`) which allows any non-admin user to bypass IP validation by simply providing a "skip" parameter. The intended logic (shown in the patch) should use AND (`admin && request.hasParameter("skip")`) to ensure only admins can skip validation.

### 2. Regular Expression Injection
At line 87, the user-controlled `ip` parameter is directly concatenated into a regex pattern without sanitization:
```java
Pattern pattern = Pattern.compile(".*(" + ip + ").*");
```

When a non-admin attacker provides a malicious input containing regex metacharacters (e.g., `*`, `(`, `)`, etc.) and sets `skip=True`, the authorization bypass allows them to skip IP validation, and their malicious input gets compiled as a regex pattern. This can cause:
- **PatternSyntaxException**: If the input contains invalid regex syntax (as seen in the crash)
- **ReDoS (Regular Expression Denial of Service)**: Crafted patterns can cause catastrophic backtracking, consuming excessive CPU time
- **Logic bypass**: Malicious patterns can match unintended data

**Attack Vector:**
The POV blob shows the attack payload:
```
ip=*&skip=True
```

This exploits both vulnerabilities:
1. The `skip=True` parameter bypasses IP validation due to the authorization logic flaw
2. The `*` character in the IP parameter causes a regex syntax error when compiled

## POV Analysis

The POV file (`pov_0.blob`) contains the following parameters (decoded from hex):
- `ip=*` (hex: `69 70 00 2a`)
- `skip=True` (hex: `73 6b 69 70 00 54 72 75 65`)

This payload:
1. Sets `ip` to `*`, a regex metacharacter that will cause a PatternSyntaxException
2. Sets `skip` to `True` to bypass the IP validation check (exploiting the authorization flaw)
3. Results in the pattern `.*(*).* ` being compiled, which contains a dangling metacharacter

## Patch Analysis

The patch file shows the fix at line 79 (within the root_cause location):

```diff
-        if (admin || request.hasParameter("skip")) {
+        if (admin && request.hasParameter("skip")) {
```

This changes the logic from OR to AND, ensuring that:
- Only administrators can use the "skip" parameter
- Non-admin users cannot bypass IP validation regardless of what parameters they provide

**Note**: The patch does NOT add `Pattern.quote()` to sanitize the regex input. This means:
- The authorization bypass is fixed (non-admins can't skip validation)
- The regex injection at line 87 still exists for admin users
- However, line 82 validation (`!isValidIPFormat(ip)`) now executes for non-admins, preventing malicious regex input from reaching line 87

The fix is effective because:
1. Non-admins must pass `isValidIPFormat(ip)` check (line 82)
2. The `isValidIPFormat()` method uses `InetAddress.getByName(ip)` which rejects regex metacharacters
3. Only admins (trusted users) can skip validation and potentially inject regex patterns

## Recommendations
- **Suggested CWEs**: [CWE-185, CWE-1333, CWE-862]
- **Vulnerability Name**: Regular Expression Injection via Authorization Bypass in AccessFilter
- **Additional Hardening**: Consider using `Pattern.quote(ip)` at line 87 to escape all regex metacharacters, even for admin users: `Pattern pattern = Pattern.compile(".*(" + Pattern.quote(ip) + ").*");`