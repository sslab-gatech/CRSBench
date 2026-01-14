# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: BatikOne
- **Vulnerability Type**: Server Side Request Forgery (SSRF)
- **Origin**: 1-day
- **Release Date**: 09/22/2022
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2022-38398
  - https://issues.apache.org/jira/browse/BATIK-1331
  - https://seclists.org/oss-sec/2022/q3/221

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Crash Location**: Multiple locations in the call stack, with the vulnerability triggered at `org.apache.batik.util.ParsedURL.openStream()` -> `org.apache.batik.bridge.SVGImageElementBridge.openStream()` 
- **Vulnerable Function**: `DefaultExternalResourceSecurity` constructor (security check bypass)
- **DEDUP Token**: c6a18ed34d3cc2e3

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
	at java.base/sun.net.www.protocol.jar.URLJarFile.retrieve(URLJarFile.java:213)
	at java.base/sun.net.www.protocol.jar.URLJarFile.getJarFile(URLJarFile.java:74)
	at java.base/sun.net.www.protocol.jar.JarFileFactory.get(JarFileFactory.java:153)
	at java.base/sun.net.www.protocol.jar.JarURLConnection.connect(JarURLConnection.java:131)
	at java.base/sun.net.www.protocol.jar.JarURLConnection.getInputStream(JarURLConnection.java:175)
	at org.apache.batik.util.ParsedURLData.openStreamInternal(ParsedURLData.java:554)
	at org.apache.batik.util.ParsedURLData.openStream(ParsedURLData.java:476)
	at org.apache.batik.util.ParsedURL.openStream(ParsedURL.java:440)
	at org.apache.batik.bridge.SVGImageElementBridge.openStream(SVGImageElementBridge.java:414)
	at org.apache.batik.bridge.SVGImageElementBridge.createImageGraphicsNode(SVGImageElementBridge.java:244)
	at org.apache.batik.bridge.SVGImageElementBridge.buildImageGraphicsNode(SVGImageElementBridge.java:179)
	at org.apache.batik.bridge.SVGImageElementBridge.createGraphicsNode(SVGImageElementBridge.java:121)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: batik-bridge/src/main/java/org/apache/batik/bridge/SVGImageElementBridge.java
- **Function**: openStream
- **Line Range**: 409-416
- **Column Range**: N/A (Java)

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: batik-bridge/src/main/java/org/apache/batik/bridge/DefaultExternalResourceSecurity.java
- **Function**: DefaultExternalResourceSecurity (constructor)
- **Line Range**: 73-98
- **Column Range**: N/A (Java)

### Code Context

**Crash Site (SVGImageElementBridge.java:409-416):**
```java
protected ProtectedStream openStream(Element e, ParsedURL purl)
    throws IOException {
    List mimeTypes = new ArrayList
        (ImageTagRegistry.getRegistry().getRegisteredMimeTypes());
    mimeTypes.addAll(MimeTypeConstants.MIME_TYPES_SVG_LIST);
    InputStream reference = purl.openStream(mimeTypes.iterator());
    return new ProtectedStream(reference);
}
```

**Root Cause (DefaultExternalResourceSecurity.java:73-98):**
```java
public DefaultExternalResourceSecurity(ParsedURL externalResourceURL,
                                       ParsedURL docURL){
    // Make sure that the archives comes from the same host
    // as the document itself
    if (docURL == null) {
        se = new SecurityException
            (Messages.formatMessage(ERROR_CANNOT_ACCESS_DOCUMENT_URL,
                                    new Object[]{externalResourceURL}));
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
}
```

**Vulnerable Behavior**: When a jar protocol URL is used (e.g., `jar:http://jazzer.example.com/f.jar!/`), the `getHost()` method returns `null` for the jar URL itself. The security check at line 85-86 fails to properly validate this case, allowing the jar URL to bypass the same-origin security check. The condition `(docHost != externalResourceHost)` evaluates to true when both are null, but the subsequent check `((docHost == null) || (!docHost.equals(externalResourceHost)))` also evaluates to true. However, the final check only blocks non-data protocol URLs when they have different hosts, missing the case where `externalResourceHost` is null due to jar protocol wrapping.

## CWE Classification
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-610**: Externally Controlled Reference to a Resource in Another Sphere
- **CWE-20**: Improper Input Validation

## Vulnerability Description

This vulnerability (CVE-2022-38398, BATIK-1331) is a Server-Side Request Forgery (SSRF) in Apache Batik 1.14 that allows attackers to bypass the `DefaultExternalResourceSecurity` security controls and make unauthorized network requests. 

The vulnerability occurs when processing SVG files that contain `<image>` elements with `xlink:href` attributes using the jar protocol (e.g., `jar:http://attacker.com/malicious.jar!/`). The jar protocol URL wrapping causes `ParsedURL.getHost()` to return `null`, which allows the URL to bypass the same-origin security check in the `DefaultExternalResourceSecurity` constructor.

**Attack Vector**: An attacker can craft a malicious SVG file with a jar protocol URL pointing to an external server. When Batik processes this SVG, it will:
1. Parse the jar URL without properly extracting the embedded HTTP URL's host
2. Bypass the same-origin security check because `getHost()` returns null
3. Make an HTTP connection to the attacker's server
4. Potentially exfiltrate sensitive information or access internal services

**Impact**: 
- Information disclosure through SSRF
- Access to internal network resources
- Potential for further exploitation through remote class loading

**CVSS Score**: 5.3 (MEDIUM) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

## POV Analysis

The proof-of-vulnerability test case (`pov_0.blob`) is a malicious SVG file:

```xml
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="450" height="500" viewBox="0 0 450 500">
  <image width="50" height="50" xlink:href="jar:http://jazzer.example.com/f.jar!/">
  </image>
</svg>
```

This SVG contains an `<image>` element with a jar protocol URL in the `xlink:href` attribute. When Batik processes this SVG:
1. It attempts to load the image from the jar URL
2. The jar protocol wraps an HTTP URL to `jazzer.example.com`
3. The security check fails to extract the host from the jar URL
4. Batik makes an HTTP connection to the external domain, demonstrating the SSRF vulnerability

The Jazzer fuzzer's SSRF sanitizer detects this unauthorized network connection and reports it as a security issue.

## Patch Analysis

The patch (from commit bfbccb6ad213c1c2dea4ce6e9210f057e5ac1229) fixes the vulnerability by properly extracting the host from jar protocol URLs:

**File**: `batik-bridge/src/main/java/org/apache/batik/bridge/DefaultExternalResourceSecurity.java`

**Changes**:
1. Added imports for `java.net.URI` and `java.net.URISyntaxException`
2. Added a check after line 83 (in the patched version, lines 84-91):

```java
if (externalResourceHost == null && !DATA_PROTOCOL.equals(externalResourceURL.getProtocol())) {
    try {
        externalResourceHost = new URI(externalResourceURL.getPath()).getHost();
    } catch (URISyntaxException e) {
        throw new RuntimeException(e);
    }
}
```

**Fix Logic**: When `getHost()` returns null for the external resource URL and the protocol is not "data", the patch extracts the path from the jar URL (which contains the embedded HTTP URL) and parses it as a URI to get the actual host. This ensures that jar protocol URLs like `jar:http://example.com/f.jar!/` are properly validated against the document's origin.

**Effect**: After the patch, jar protocol URLs are properly parsed to extract the embedded URL's host, and the same-origin check correctly identifies and blocks cross-origin jar URLs, preventing the SSRF attack.

## Recommendations
- **Suggested CWEs**: [CWE-918, CWE-610, CWE-20]
- **Vulnerability name**: "Apache Batik Jar Protocol SSRF in DefaultExternalResourceSecurity"
- **Severity**: MEDIUM (CVSS 5.3)
- **Origin**: 1-day (CVE-2022-38398)
- **Release Date**: 09/22/2022
- **Fixed Version**: Apache Batik 1.15