# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: OlingoOneFDP
- **Vulnerability Type**: Server-Side Request Forgery (SSRF)
- **Origin**: 1-day
- **Release Date**: 01/09/2020
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2020-1925
  - https://blog.gypsyengineer.com/en/security/cve-2020-1925-ssrf-in-apache-olingo.html

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Crash Location**: AsyncRequestWrapperImpl.java, method `isDone()` at line 171 (call to `checkMonitor(location)`)
- **Vulnerable Function**: `retrieveMonitorDetails()` and `checkMonitor()`
- **DEDUP Token**: 35079308c04d348b

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
Attempted connection to: jazzer.example.com:443
Requests to destinations based on untrusted data could lead to exfiltration of sensitive data or exposure of internal services.

	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrf(ServerSideRequestForgery.java:127)
	at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrfSocket(ServerSideRequestForgery.java:71)
	at java.base/java.net.Socket.connect(Socket.java:633)
	at java.base/sun.security.ssl.SSLSocketImpl.connect(SSLSocketImpl.java:299)
	at org.apache.http.conn.ssl.SSLSocketFactory.connectSocket(SSLSocketFactory.java:414)
	at org.apache.http.impl.conn.DefaultClientConnectionOperator.openConnection(DefaultClientConnectionOperator.java:180)
	at org.apache.http.impl.conn.ManagedClientConnectionImpl.open(ManagedClientConnectionImpl.java:294)
	at org.apache.http.impl.client.DefaultRequestDirector.tryConnect(DefaultRequestDirector.java:643)
	at org.apache.http.impl.client.DefaultRequestDirector.execute(DefaultRequestDirector.java:479)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:906)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:805)
	at org.apache.http.impl.client.AbstractHttpClient.execute(AbstractHttpClient.java:784)
	at org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl.executeHttpRequest(AsyncRequestWrapperImpl.java:303)
	at org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl.checkMonitor(AsyncRequestWrapperImpl.java:297)
	at org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl$AsyncResponseWrapperImpl.isDone(AsyncRequestWrapperImpl.java:171)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: lib/client-core/src/main/java/org/apache/olingo/client/core/communication/request/v4/AsyncRequestWrapperImpl.java
- **Function**: checkMonitor
- **Line Range**: 289-298
- **Column Range**: Not applicable (Jazzer hook detected the SSRF at socket connection level)

**Description**: The crash occurs when the application attempts to make an HTTP request to an attacker-controlled URL. The SSRF is detected by Jazzer's ServerSideRequestForgery sanitizer when attempting to establish a socket connection.

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: lib/client-core/src/main/java/org/apache/olingo/client/core/communication/request/v4/AsyncRequestWrapperImpl.java
- **Function**: retrieveMonitorDetails
- **Line Range**: 259-262
- **Column Range**: Not applicable

**Description**: The root cause is at line 262 where the Location header value is directly used to create a URI without any validation that it points to the same server/domain as the original request.

### Code Context

**Root Cause (Line 259-262):**
```java
private void retrieveMonitorDetails(final HttpResponse res) {
  Header[] headers = res.getHeaders(HeaderName.location.toString());
  if (ArrayUtils.isNotEmpty(headers)) {
    this.location = URI.create(headers[0].getValue());  // ← VULNERABLE: No validation
  } else {
    throw new AsyncRequestException(
            "Invalid async request response. Monitor URL '" + headers[0].getValue() + "'");
  }
  // ... rest of the method
}
```

**Crash Site (Line 289-297):**
```java
protected final HttpResponse checkMonitor(final URI location) {
  if (location == null) {
    throw new AsyncRequestException("Invalid async request response. Missing monitor URL");
  }

  final HttpUriRequest monitor = odataClient.getConfiguration().getHttpUriRequestFactory().
          createHttpUriRequest(HttpMethod.GET, location);  // ← Uses attacker-controlled URI

  return executeHttpRequest(httpClient, monitor);  // ← Makes the SSRF request
}
```

## CWE Classification
- **CWE-918**: Server-Side Request Forgery (SSRF) - Primary classification
- **CWE-20**: Improper Input Validation - The Location header is not validated before use
- **CWE-601**: URL Redirection to Untrusted Site ('Open Redirect') - Related weakness

## Vulnerability Description

This is a **Server-Side Request Forgery (SSRF)** vulnerability in Apache Olingo versions 4.0.0 to 4.7.0, tracked as **CVE-2020-1925**. 

The vulnerability exists in the `AsyncRequestWrapperImpl` class which handles asynchronous OData requests. When the server responds with an HTTP 202 (Accepted) status code for an asynchronous operation, the client expects a `Location` header containing a monitor URL to check the operation status.

**The vulnerability occurs because:**
1. The `retrieveMonitorDetails()` method reads the `Location` header from the HTTP response (line 262)
2. It creates a URI directly from the header value **without any validation**
3. The attacker-controlled URI is stored in `this.location`
4. Later, the `checkMonitor()` method uses this URI to make HTTP GET requests (line 295)
5. These requests can target arbitrary URLs, including internal resources

**Attack scenario:**
1. Attacker sets up a malicious OData server
2. Victim's application connects to the malicious server using Apache Olingo client
3. Malicious server responds with HTTP 202 and a crafted `Location` header pointing to:
   - Internal IP addresses (e.g., `http://192.168.1.1/admin`)
   - Cloud metadata services (e.g., `http://169.254.169.254/latest/meta-data/`)
   - Any arbitrary external host
4. The Olingo client automatically makes requests to the attacker-controlled URL
5. Attacker can potentially access internal services or exfiltrate sensitive data

## POV Analysis

The POV (Proof of Vulnerability) file contains: `jazzer.example.com   a`

This POV demonstrates the vulnerability by:
- Triggering the application to parse input that causes an async OData request
- The fuzzing harness likely mocks an HTTP response with a Location header pointing to `jazzer.example.com:443`
- Jazzer's SSRF sanitizer detects the attempted connection to the attacker-controlled domain
- The SSRF is successfully triggered, proving the vulnerability exists

The POV is minimal but effective - it only needs to provide input that results in a malicious Location header being processed.

## Patch Analysis

The patch adds three layers of defense:

**1. Null check for target URI (line 17):**
```java
Objects.requireNonNull(this.uri, "Target URI can't be null");
```

**2. New validation method `checkLocation()` (lines 25-36):**
```java
private URI checkLocation(URI uri) {
  if (!this.uri.getScheme().equals(uri.getScheme())) {
    throw new AsyncRequestException("Unexpected scheme in the Location header");
  }
  if (!this.uri.getHost().equals(uri.getHost())) {
    throw new AsyncRequestException("Unexpected host name in the Location header");
  }
  if (this.uri.getPort() != uri.getPort()) {
    throw new AsyncRequestException("Unexpected port in the Location header");
  }
  return uri;
}
```

This method validates that the Location header URL has:
- Same **scheme** (http/https) as the original request
- Same **host** as the original request
- Same **port** as the original request

**3. Apply validation when parsing Location header (lines 44-46, 57):**
```java
URI createLocation(String string) {
  return checkLocation(URI.create(string));
}

// Used at line 57:
this.location = createLocation(headers[0].getValue());
```

The fix ensures that the client will only follow Location headers that point back to the same server it originally connected to, preventing SSRF attacks.

## Recommendations

- **Suggested CWEs**: [CWE-918, CWE-20, CWE-601]
- **Vulnerability Name**: Server-Side Request Forgery via Unvalidated Location Header in AsyncRequestWrapperImpl
- **Severity**: HIGH (CVSS 7.5)
- **Fixed Version**: Apache Olingo 4.7.1
- **Mitigation**: Validate that Location headers in async responses point to the same scheme, host, and port as the original request URL