# Vulnerability Analysis for cpv_3

## Summary
- **CPV ID**: cpv_3
- **Harness**: JenkinsThreeFDP
- **Vulnerability Type**: Server-Side Request Forgery (SSRF)
- **Origin**: 1-day
- **Release Date**: 02/14/2018
- **CVE**: CVE-2018-1000067
- **References**: 
  - https://www.jenkins.io/security/advisory/2018-02-14/
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1000067

## Crash Log Analysis

- **Error Type**: FuzzerSecurityIssueMedium - Server Side Request Forgery (SSRF)
- **Detection**: Jazzer sanitizer detected attempted connection to untrusted destination
- **Attempted Connection**: jazzer.example.com:8080
- **Crash Location**: ProxyConfiguration.java (doValidateProxy method)
- **Vulnerable Function**: `doValidateProxy`
- **DEDUP Token**: 7b1e9ac390a60c55

### Stack Trace

The key portion of the stack trace shows:
```
com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
Attempted connection to: jazzer.example.com:8080
Requests to destinations based on untrusted data could lead to exfiltration of sensitive data or exposure of internal services.

	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrf(ServerSideRequestForgery.java:127)
	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrfHttpConnection(ServerSideRequestForgery.java:92)
	...
	at java.net.http/jdk.internal.net.http.HttpClientFacade.send(HttpClientFacade.java:123)
	at hudson.ProxyConfiguration$DescriptorImpl2.doValidateProxy(ProxyConfiguration.java:593)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.testProxyConfiguration(JenkinsThreeFDP.java:148)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: jenkins/core/src/main/java/hudson/ProxyConfiguration.java
- **Function**: doValidateProxy
- **Line Range**: 593-593
- **Column Range**: 1-100

This is where the HTTP request is actually sent, triggering the SSRF detection:
```java
HttpResponse<Void> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.discarding());
```

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: jenkins/core/src/main/java/hudson/ProxyConfiguration.java
- **Function**: doValidateProxy
- **Line Range**: 529-533
- **Column Range**: 1-100

This is where the missing permission check should have been. The patch adds the permission check at the start of the function.

### Code Context

**Vulnerable code (before patch):**
```java
@RequirePOST
@Restricted(NoExternalUse.class)
public FormValidation doValidateProxy(
    @QueryParameter("testUrl") String testUrl,
    StaplerRequest request,
    StaplerResponse response) throws InterruptedException {

    testUrl = Util.fixEmptyAndTrim(testUrl);
    if (testUrl == null) {
        return FormValidation.error(Messages.ProxyConfiguration_TestUrlRequired());
    }
    // ... continues to make HTTP request without permission check
```

**Fixed code (after patch):**
```java
@RequirePOST
@Restricted(NoExternalUse.class)
public FormValidation doValidateProxy(
    @QueryParameter("testUrl") String testUrl,
    StaplerRequest request,
    StaplerResponse response) throws InterruptedException {

    j.checkPermission(Jenkins.ADMINISTER);  // <-- Added permission check

    testUrl = Util.fixEmptyAndTrim(testUrl);
    if (testUrl == null) {
        return FormValidation.error(Messages.ProxyConfiguration_TestUrlRequired());
    }
    // ... continues to make HTTP request
```

## CWE Classification

- **CWE-918**: Server-Side Request Forgery (SSRF)
  - Primary classification for the vulnerability type
- **CWE-862**: Missing Authorization
  - The root cause - lack of permission check allowing unauthorized users to trigger the SSRF

## Vulnerability Description

This is an improper authorization vulnerability in Jenkins versions 2.106 and earlier (and LTS 2.89.3 and earlier) that enables Server-Side Request Forgery attacks. The `doValidateProxy` method in `ProxyConfiguration.java` validates proxy configuration by making HTTP requests to user-specified URLs but fails to check if the user has sufficient permissions to perform this operation.

**Attack Scenario:**
1. An attacker with only Overall/Read access to Jenkins (minimal permissions) can access the proxy configuration form
2. The attacker provides a malicious URL (e.g., `http://jazzer.example.com:8080` or internal service URLs)
3. Jenkins makes an HTTP GET request to the attacker-specified URL
4. The form validation returns either a success message or HTTP status code, leaking information about the target
5. This allows attackers to:
   - Probe internal network services not directly accessible
   - Exfiltrate sensitive data
   - Port scan internal infrastructure
   - Access cloud metadata endpoints (e.g., AWS EC2 metadata)

**Important Note:** The attacker must provide their own proxy configuration; they cannot reuse existing configurations.

**Impact:**
- Information disclosure through HTTP status codes
- Network reconnaissance of internal services
- Potential data exfiltration

**Fix:**
The patch adds a permission check at the beginning of the `doValidateProxy` method:
```java
j.checkPermission(Jenkins.ADMINISTER);
```
This ensures only users with Overall/Administer permissions can trigger the proxy validation, preventing unauthorized SSRF attacks.

## POV Analysis

The POV file (`pov_0.blob`) contains:
```
name jazzer.example.com port 8080 http://localhost:8888
```

This POV demonstrates the vulnerability by:
1. Providing proxy parameters: `name=jazzer.example.com`, `port=8080`
2. Specifying a test URL: `http://localhost:8888`
3. The harness passes these to `doValidateProxy` without proper authorization
4. Jenkins attempts to connect to the external domain `jazzer.example.com:8080`
5. Jazzer's SSRF sanitizer detects the unauthorized outbound connection and flags it

## Patch Analysis

The patch (`patch_0.diff`) is minimal and surgical:

```diff
@@ -531,6 +531,8 @@ public final class ProxyConfiguration extends AbstractDescribableImpl<ProxyConfi
             StaplerRequest request,
             StaplerResponse response) throws InterruptedException {
 
+            j.checkPermission(Jenkins.ADMINISTER);
+
             testUrl = Util.fixEmptyAndTrim(testUrl);
```

**Analysis:**
- The fix adds a single line at the start of `doValidateProxy` method (line 534 after the patch)
- `j.checkPermission(Jenkins.ADMINISTER)` throws an `AccessDeniedException` if the user lacks administrator privileges
- This prevents unauthorized users from triggering HTTP requests to arbitrary URLs
- The fix is consistent with Jenkins' security model where sensitive operations require admin permissions

## Recommendations

- **Suggested CWEs**: [CWE-918, CWE-862]
- **Vulnerability Name**: Jenkins ProxyConfiguration SSRF due to Missing Authorization
- **Severity**: Medium (CVSS 3.1: 5.3, CVSS 2.0: 5.0)
- **Credit**: Daniel Beck from CloudBees, Inc.
- **Fixed in**: Jenkins 2.107+ (weekly), Jenkins LTS 2.89.4+