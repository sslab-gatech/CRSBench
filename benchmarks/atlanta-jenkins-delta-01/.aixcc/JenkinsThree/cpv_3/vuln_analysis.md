# Vulnerability Analysis for cpv_3

## Summary
- **CPV ID**: cpv_3
- **Harness**: JenkinsThree
- **Vulnerability Type**: Server Side Request Forgery (SSRF) - Missing Permission Check
- **Origin**: 1-day
- **Release Date**: 02/15/2018
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1000067
  - https://www.jenkins.io/security/advisory/2018-02-14/

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Detection Location**: Jazzer SSRF sanitizer detected an attempted connection to untrusted destination
- **Attempted Connection**: jazzer.example.com:8080
- **DEDUP Token**: 8a3b20b49697cae8

### Stack Trace
The vulnerability is triggered through the following call chain:
```
at hudson.ProxyConfiguration$DescriptorImpl2.doValidateProxy(ProxyConfiguration.java:593)
at com.aixcc.jenkins.harnesses.three.JenkinsThree.testProxyConfiguration(JenkinsThree.java:148)
at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzz(JenkinsThree.java:91)
at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzzerTestOneInput(JenkinsThree.java:79)
```

The actual SSRF occurs when the HTTP client attempts to connect:
```
at java.net.http/jdk.internal.net.http.HttpClientFacade.send(HttpClientFacade.java:123)
at hudson.ProxyConfiguration$DescriptorImpl2.doValidateProxy(ProxyConfiguration.java:593)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: jenkins/core/src/main/java/hudson/ProxyConfiguration.java
- **Function**: DescriptorImpl2.doValidateProxy
- **Line Range**: 529-533
- **Column Range**: N/A (Java method signature)

### Code Context
The vulnerability exists at the beginning of the `doValidateProxy` method where there is a **missing permission check**:

```java
@RequirePOST
@Restricted(NoExternalUse.class)
public FormValidation doValidateProxy(
    @QueryParameter("testUrl") String testUrl,
    StaplerRequest request,
    StaplerResponse response) throws InterruptedException {

    // MISSING: j.checkPermission(Jenkins.ADMINISTER);
    
    testUrl = Util.fixEmptyAndTrim(testUrl);
    if (testUrl == null) {
        return FormValidation.error(Messages.ProxyConfiguration_TestUrlRequired());
    }
    URI uri;
    try {
        uri = new URI(testUrl);
    } catch (URISyntaxException e) {
        return FormValidation.error(e, Messages.ProxyConfiguration_MalformedTestUrl(testUrl));
    }
    // ... continues to make HTTP request using HttpClient ...
    HttpResponse<Void> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.discarding());
```

The method processes a user-supplied `testUrl` parameter and makes an HTTP request to it without first verifying that the user has administrator permissions. This allows any user with Overall/Read access to trigger arbitrary HTTP requests from the Jenkins server.

## CWE Classification
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-862**: Missing Authorization

## Vulnerability Description

This is a **Server-Side Request Forgery (SSRF)** vulnerability caused by a **missing authorization check** in Jenkins' proxy configuration validation endpoint.

### Root Cause
The `doValidateProxy` method in `ProxyConfiguration.DescriptorImpl2` class fails to verify that the calling user has administrator privileges before processing the request. This allows any authenticated user with basic read access (Overall/Read permission) to invoke the method.

### Attack Vector
1. An attacker with minimal Jenkins permissions (Overall/Read) can access the proxy validation endpoint
2. The attacker provides a malicious URL in the `testUrl` parameter
3. Jenkins server makes an HTTP GET request to the attacker-controlled URL
4. The HTTP response status code is returned to the attacker, revealing whether the request succeeded

### Impact
- **Network Probing**: Attackers can scan internal networks and services that are only accessible from the Jenkins server
- **Information Disclosure**: HTTP status codes reveal whether target URLs/services exist and respond
- **Port Scanning**: Can be used to identify open ports on internal systems
- **Bypass Firewall**: Leverages Jenkins server's network position to access resources behind firewalls

### Mitigation
The patch adds a permission check at the beginning of the `doValidateProxy` method:
```java
j.checkPermission(Jenkins.ADMINISTER);
```

This ensures only users with administrator privileges can trigger proxy validation requests, preventing unauthorized SSRF attacks.

## POV Analysis

**POV File**: `pov_0.blob`
```
name jazzer.example.com port 8080 http://localhost:8888
```

This POV demonstrates the SSRF vulnerability by:
1. Setting up proxy parameters with attacker-controlled values:
   - Proxy name: `jazzer.example.com`
   - Proxy port: `8080`
   - Test URL: `http://localhost:8888`

2. The fuzzer harness parses these values and passes them to `doValidateProxy`:
   - `parts[0]` = "name", `parts[1]` = "jazzer.example.com"
   - `parts[2]` = "port", `parts[3]` = "8080"
   - `parts[4]` = "http://localhost:8888"

3. Without the permission check, Jenkins attempts to connect to `localhost:8888` via the specified proxy, triggering the Jazzer SSRF sanitizer which detects the unauthorized network connection attempt.

## Patch Analysis

**Patch File**: `patch_0.diff`

The patch adds a single critical line at the beginning of the `doValidateProxy` method:

```diff
@@ -531,6 +531,8 @@ public final class ProxyConfiguration extends AbstractDescribableImpl<ProxyConfi
             StaplerRequest request,
             StaplerResponse response) throws InterruptedException {
 
+            j.checkPermission(Jenkins.ADMINISTER);
+
             testUrl = Util.fixEmptyAndTrim(testUrl);
```

**Analysis**:
- **Location**: Line 533-534 (after method signature, before any processing)
- **Fix**: Adds authorization check requiring `Jenkins.ADMINISTER` permission
- **Effect**: Throws `AccessDeniedException3` if user lacks admin privileges, preventing SSRF exploitation
- **Security Principle**: Fail-safe defaults - deny access unless explicitly authorized

This is a textbook example of a **missing function-level access control** vulnerability (OWASP A05:2021), where the fix involves adding the missing authorization check before any sensitive operation is performed.

## Recommendations
- **Suggested CWEs**: [CWE-918, CWE-862]
- **Vulnerability Name**: Missing Permission Check in Proxy Configuration Validation Leading to SSRF
- **CVE Reference**: CVE-2018-1000067
- **Security Advisory**: SECURITY-506 (Jenkins Security Advisory 2018-02-14)

---

**Analysis Complete**: This is a real-world 1-day vulnerability (CVE-2018-1000067) affecting Jenkins core. The vulnerability demonstrates a classic authorization bypass leading to SSRF, where the absence of a permission check allows low-privileged users to abuse server functionality for network reconnaissance and potential data exfiltration.