# Vulnerability Analysis for cpv_11

## Summary
- **CPV ID**: cpv_11
- **Harness**: JenkinsThree
- **Vulnerability Type**: Regular Expression Injection (ReDoS)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueLow: Regular Expression Injection
- **Crash Location**: AccessFilter.java:87
- **Vulnerable Function**: doGet
- **DEDUP Token**: a0eef6f91a9b7ce8

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Regular Expression Injection
Regular expression patterns that contain unescaped untrusted input can consume
arbitrary amounts of CPU time. To properly escape the input, wrap it with
Pattern.quote(...).
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.hookInternal(RegexInjection.kt:164)
	at com.code_intelligence.jazzer.sanitizers.RegexInjection.patternHook(RegexInjection.kt:85)
	at io.jenkins.plugins.toyplugin.AccessFilter.doGet(AccessFilter.java:87)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.testAccessFilter(JenkinsThree.java:302)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzz(JenkinsThree.java:106)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzzerTestOneInput(JenkinsThree.java:79)
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

### Location 1 (crash_site and root_cause)
- **Type**: crash_site, root_cause
- **File Path**: plugins/toy-plugin/src/main/java/io/jenkins/plugins/toyplugin/AccessFilter.java
- **Function**: doGet
- **Line Range**: 87-87
- **Column Range**: 1-57

### Code Context
```java
70:    @RequirePOST
71:    public void doGet(StaplerRequest request, StaplerResponse response) throws IOException {
72:        if (!request.hasParameter("ip")) {
73:            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
74:            return;
75:        }
76:        String ip = request.getParameter("ip");
77:        boolean skip = false;
78:        boolean admin = getJenkins().hasPermission(Jenkins.ADMINISTER);
79:        if (admin || request.hasParameter("skip")) {  // Authorization bypass vulnerability
80:            skip = Boolean.parseBoolean(request.getParameter("skip"));
81:        }
82:        if (!isValidIPFormat(ip) && !skip) {
83:            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
84:            return;
85:        }
86:
87:        Pattern pattern = Pattern.compile(".*(" + ip + ").*");  // VULNERABLE: Unescaped user input
88:        List<String> result = new ArrayList<>();
89:        for (String data : access) {
90:            if (!pattern.matcher(data).matches()) {
91:                continue;
92:            }
93:            result.add(data);
94:        }
95:        Gson gson = new Gson();
96:        response.getWriter().write(gson.toJson(result));
97:    }
```

## CWE Classification
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS - Regular Expression Denial of Service)
- **CWE-94**: Improper Control of Generation of Code ('Code Injection') - regex pattern injection is a form of code injection

## Vulnerability Description

This vulnerability involves **Regular Expression Injection** in the Jenkins toy-plugin's AccessFilter component. The `doGet` method at line 87 constructs a regex pattern by directly concatenating unsanitized user input from the `ip` parameter:

```java
Pattern pattern = Pattern.compile(".*(" + ip + ").*");
```

### Attack Vector

An attacker can inject malicious regex metacharacters through the `ip` parameter. For example, the POV uses the input `ip * skip True`, which results in the malformed regex pattern `.*(*).*`. The unescaped `*` is a regex metacharacter (repetition operator) that causes a `PatternSyntaxException` when it appears without a preceding character to repeat.

### Impact

1. **Denial of Service (DoS)**: Malicious regex patterns can cause catastrophic backtracking, leading to CPU exhaustion
2. **Application Crash**: Invalid regex syntax causes `PatternSyntaxException`, crashing the endpoint
3. **ReDoS Attack**: Carefully crafted patterns could cause exponential time complexity in matching

### Contributing Factor - Authorization Bypass

The patch file shows an additional vulnerability on line 79:
```java
if (admin || request.hasParameter("skip")) {  // BEFORE patch
```

This line allows non-admin users to bypass IP validation by simply including a `skip` parameter in the request. The patch changes it to:
```java
if (admin && request.hasParameter("skip")) {  // AFTER patch
```

This authorization bypass amplifies the regex injection vulnerability by allowing unauthorized users to bypass the `isValidIPFormat()` validation check, making it easier to inject malicious regex patterns.

### Root Cause

The vulnerability exists because:
1. User input (`ip` parameter) is not sanitized before being used in regex compilation
2. Java's `Pattern.compile()` does not automatically escape special regex characters
3. The proper fix would be to use `Pattern.quote(ip)` to escape all regex metacharacters

## POV Analysis

The proof-of-vulnerability file (`pov_0.blob`) contains:
```
   Mip * skip True
```

This input is parsed as:
- `ip` parameter: `*` (a regex metacharacter)
- `skip` parameter: `True`

When processed:
1. The `skip` parameter bypasses IP validation due to the authorization bug
2. The unescaped `*` is injected into the regex: `.*(*).*`
3. The `*` metacharacter without a preceding atom causes `PatternSyntaxException`
4. Jazzer's RegexInjection sanitizer detects this as a security issue

## Patch Analysis

The provided patch (`patch_0.diff`) addresses the **authorization bypass** vulnerability but **not the regex injection itself**:

```diff
-        if (admin || request.hasParameter("skip")) {
+        if (admin && request.hasParameter("skip")) {
```

**What the patch fixes**: Changes the condition from OR to AND, requiring the user to be an admin before they can set the `skip` parameter. This prevents unauthorized users from bypassing IP validation.

**What the patch doesn't fix**: The regex injection on line 87 remains unpatched. The proper fix would be:
```java
Pattern pattern = Pattern.compile(".*(" + Pattern.quote(ip) + ").*");
```

The patch only provides **defense in depth** by making it harder for non-admin users to reach the vulnerable code path with malicious input, but doesn't eliminate the root cause.

## Recommendations

### Suggested CWEs
- CWE-1333 (Inefficient Regular Expression Complexity / ReDoS)
- CWE-94 (Improper Control of Generation of Code)

### Vulnerability Name
"Regular Expression Injection in Jenkins toy-plugin AccessFilter"

### Complete Fix Required
To fully remediate this vulnerability, the code should:
1. Apply the authorization fix (as shown in patch) ✓
2. **Escape user input** using `Pattern.quote()`:
   ```java
   Pattern pattern = Pattern.compile(".*(" + Pattern.quote(ip) + ").*");
   ```
3. Consider input validation/sanitization before regex compilation
4. Add error handling for `PatternSyntaxException`

### Security Best Practices
- Never concatenate user input directly into regex patterns
- Use `Pattern.quote()` to escape literal strings in regex
- Implement proper authorization checks (admin-only for sensitive operations)
- Apply defense-in-depth: multiple layers of validation