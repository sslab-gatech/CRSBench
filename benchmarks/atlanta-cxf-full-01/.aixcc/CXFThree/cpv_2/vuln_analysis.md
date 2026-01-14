# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: CXFThree
- **Vulnerability Type**: Server-Side Request Forgery (SSRF)
- **Origin**: 1-day
- **CVE**: CVE-2024-29736
- **Release Date**: 07/19/2024
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2024-29736
  - https://github.com/advisories/GHSA-5m3j-pxh7-455p
  - https://cxf.apache.org/security-advisories.data/CVE-2024-29736.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Attempted Connection**: jazzer.example.com:443
- **Vulnerable Function**: `getExistingResource` (called from `doFilter`)
- **Crash Location**: org/apache/cxf/jaxrs/utils/ResourceUtils.java:577 (url.openStream())
- **DEDUP Token**: 204abc86503e52b9

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
Attempted connection to: jazzer.example.com:443
Requests to destinations based on untrusted data could lead to exfiltration of sensitive data or exposure of internal services.

	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrf(ServerSideRequestForgery.java:127)
	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrfSocket(ServerSideRequestForgery.java:71)
	at java.base/java.net.Socket.connect(Socket.java:633)
	at java.base/sun.security.ssl.SSLSocketImpl.connect(SSLSocketImpl.java:299)
	at java.base/sun.security.ssl.BaseSSLSocketImpl.connect(BaseSSLSocketImpl.java:174)
	at java.base/sun.net.NetworkClient.doConnect(NetworkClient.java:183)
	at java.base/sun.net.www.http.HttpClient.openServer(HttpClient.java:498)
	at java.base/sun.net.www.http.HttpClient.openServer(HttpClient.java:603)
	at java.base/sun.net.www.protocol.https.HttpsClient.<init>(HttpsClient.java:266)
	at java.base/sun.net.www.protocol.https.HttpsClient.New(HttpsClient.java:380)
	at java.base/sun.net.www.protocol.https.AbstractDelegateHttpsURLConnection.getNewHttpClient(AbstractDelegateHttpsURLConnection.java:189)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.plainConnect0(HttpURLConnection.java:1242)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.plainConnect(HttpURLConnection.java:1128)
	at java.base/sun.net.www.protocol.https.AbstractDelegateHttpsURLConnection.connect(AbstractDelegateHttpsURLConnection.java:175)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.getInputStream0(HttpURLConnection.java:1665)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.getInputStream(HttpURLConnection.java:1589)
	at java.base/sun.net.www.protocol.https.HttpsURLConnectionImpl.getInputStream(HttpsURLConnectionImpl.java:224)
	at java.base/java.net.URL.openStream(URL.java:1161)
	at org.apache.cxf.jaxrs.utils.ResourceUtils.getResourceStream(ResourceUtils.java:577)
	at org.apache.cxf.jaxrs.model.wadl.WadlGenerator.getExistingResource(WadlGenerator.java:1376)
	at org.apache.cxf.jaxrs.model.wadl.WadlGenerator.doFilter(WadlGenerator.java:247)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: rt/rs/description/src/main/java/org/apache/cxf/jaxrs/model/wadl/WadlGenerator.java
- **Function**: doFilter
- **Line Range**: 245-248
- **Column Range**: 1-50

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: rt/frontend/jaxrs/src/main/java/org/apache/cxf/jaxrs/utils/ResourceUtils.java
- **Function**: getResourceStream
- **Line Range**: 577-577
- **Column Range**: 1-50

### Code Context

**Root Cause - WadlGenerator.java (lines 240-250):**
```java
if (stylesheetReference != null || !docLocationMap.isEmpty()) {
    String path = ui.getPath(false);
    if (path.startsWith("/") && !path.isEmpty()) {
        path = path.substring(1);
    }
    if (stylesheetReference != null && path.endsWith(".xsl")
        || docLocationMap.containsKey(path)) {
        context.abortWith(getExistingResource(m, ui, path));  // Line 247 - vulnerable call
    }
}
```

**Vulnerable Logic - WadlGenerator.java getExistingResource (lines 1375-1377):**
```java
} else if (stylesheetReference != null && href.endsWith(".xsl")) {
    InputStream is = ResourceUtils.getResourceStream(href, m.getExchange().getBus());  // Line 1376 - passes user-controlled href
    return Response.ok().type(MediaType.APPLICATION_XML_TYPE).entity(is).build();
}
```

**Crash Site - ResourceUtils.java (lines 575-578):**
```java
public static InputStream getResourceStream(String loc, Bus bus) throws IOException {
    URL url = getResourceURL(loc, bus);
    return url == null ? null : url.openStream();  // Line 577 - SSRF occurs here
}
```

## CWE Classification
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-918** (Primary): The vulnerability allows an attacker to cause the server to make requests to arbitrary URLs, potentially accessing internal resources or performing unauthorized actions.

## Vulnerability Description

This is a **Server-Side Request Forgery (SSRF)** vulnerability in Apache CXF's WADL (Web Application Description Language) service description functionality. The vulnerability allows an attacker to force the server to make HTTP/HTTPS requests to arbitrary URLs controlled by the attacker.

**Root Cause:**
The vulnerability exists in the `doFilter` method of `WadlGenerator.java` at lines 245-247. The code improperly validates user-supplied path parameters when the `stylesheetReference` configuration is set. The vulnerable code checks if a path ends with `.xsl` but fails to validate that the path refers only to legitimate local resources.

**Vulnerable Flow:**
1. An attacker sends a GET request with a malicious path (e.g., `GET /secret.xsl` with host `https://jazzer.example.com`)
2. The `doFilter` method extracts the path from the request
3. If `stylesheetReference` is configured and the path ends with `.xsl`, it calls `getExistingResource(m, ui, path)` at line 247
4. `getExistingResource` then calls `ResourceUtils.getResourceStream(href, ...)` at line 1376, passing the attacker-controlled URL
5. `ResourceUtils.getResourceStream` opens a connection to the attacker-specified URL at line 577, causing an SSRF

**Security Impact:**
- **Data Exfiltration**: Attackers can access internal services and retrieve sensitive data
- **Internal Network Scanning**: Probe internal network resources not directly accessible from the internet
- **Credential Theft**: Access cloud metadata services (e.g., AWS EC2 metadata at 169.254.169.254)
- **Bypass Access Controls**: Access resources that should be restricted

**Attack Prerequisites:**
- The application must have `stylesheetReference` configuration parameter set (custom stylesheet configured)
- The attacker needs to craft a request with a path ending in `.xsl`

## POV Analysis

**POV File**: `pov_0.blob`
```
GET 1 https://jazzer.example.com/secret.xsl
```

This proof-of-vulnerability demonstrates the SSRF attack by:
1. Sending a GET request for a path ending in `.xsl` (`/secret.xsl`)
2. Using an external URL (`https://jazzer.example.com`) as the target
3. The server attempts to fetch this external URL, triggering the SSRF vulnerability

The Jazzer fuzzer's SSRF sanitizer detects the attempted connection to `jazzer.example.com:443`, confirming the vulnerability.

## Patch Analysis

**Patch File**: `patch_0.diff`

The patch fixes the vulnerability by implementing proper validation of the stylesheet reference:

**Before (Vulnerable - Line 245-248):**
```java
if (stylesheetReference != null && path.endsWith(".xsl")
    || docLocationMap.containsKey(path)) {
    context.abortWith(getExistingResource(m, ui, path));
}
```

**After (Fixed - Line 242-254):**
```java
if (docLocationMap.containsKey(path)) {
    context.abortWith(getExistingResource(m, ui, path));
} else if (stylesheetReference != null) {
    String theStylesheetReference = stylesheetReference;
    if (theStylesheetReference.startsWith("/")) {
        theStylesheetReference = theStylesheetReference.substring(1);
    }
    if (path.endsWith(theStylesheetReference)) {
        context.abortWith(getExistingResource(m, ui, stylesheetReference));
    }
}
```

**Key Security Improvements:**
1. **Separate Logic**: Split the `docLocationMap` check from the stylesheet validation (lines 242-243)
2. **Exact Match Validation**: Instead of checking if path ends with generic `.xsl`, it now validates that the path ends with the exact configured `stylesheetReference` value (line 251)
3. **Use Configured Value**: Pass the configured `stylesheetReference` to `getExistingResource` instead of the user-supplied `path` (line 252)
4. **Prevent Path Manipulation**: Normalize the stylesheet reference by removing leading slash (lines 246-248)

This ensures that only the pre-configured stylesheet can be accessed, preventing attackers from specifying arbitrary URLs.

## Recommendations
- **Suggested CWEs**: [CWE-918]
- **Vulnerability Name**: SSRF via WADL Stylesheet Parameter
- **Severity**: High (CVSS 8.2)
- **Affected Component**: Apache CXF WADL Generator
- **Mitigation**: Upgrade to Apache CXF version 3.5.9, 3.6.4, 4.0.5 or later

---

**Analysis completed for CPV cpv_2 in harness CXFThree.**