# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ShiroOne
- **Vulnerability Type**: Insecure Deserialization leading to Remote Code Execution via OS Command Injection
- **Origin**: 1-day
- **Release Date**: 06/07/2016
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2016-4437
  - https://shiro.apache.org/security-reports.html

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: OS Command Injection
- **Crash Location**: org.apache.shiro.mgt.AbstractRememberMeManager.convertBytesToPrincipals (line 431)
- **Vulnerable Functions**: 
  - `convertBytesToPrincipals()` - calls unsafe deserialization
  - `deserialize()` - performs unsafe Java object deserialization
  - `DefaultSerializer.deserialize()` - uses ObjectInputStream.readObject()
- **DEDUP Token**: 6fac7ab70df97695

### Stack Trace
The vulnerability is triggered through a deserialization gadget chain:

```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:60)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	at java.base/java.lang.Runtime.exec(Runtime.java:315)
	at ysoserial.Pwner1821021107502238.<clinit>(Gadgets.java)
	...
	at java.xml/com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties(TemplatesImpl.java:608)
	...
	at org.apache.commons.beanutils.BeanComparator.compare(BeanComparator.java:163)
	at java.base/java.util.PriorityQueue.siftDownUsingComparator(PriorityQueue.java:712)
	at java.base/java.util.PriorityQueue.readObject(PriorityQueue.java:801)
	...
	at org.apache.shiro.io.DefaultSerializer.deserialize(DefaultSerializer.java:77)
	at org.apache.shiro.mgt.AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514)
	at org.apache.shiro.mgt.AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431)
	at org.apache.shiro.mgt.AbstractRememberMeManager.getRememberedPrincipals(AbstractRememberMeManager.java:396)
	at org.apache.shiro.mgt.DefaultSecurityManager.getRememberedIdentity(DefaultSecurityManager.java:604)
	at org.apache.shiro.mgt.DefaultSecurityManager.resolvePrincipals(DefaultSecurityManager.java:492)
	at org.apache.shiro.mgt.DefaultSecurityManager.createSubject(DefaultSecurityManager.java:342)
	at org.apache.shiro.web.servlet.AbstractShiroFilter.createSubject(AbstractShiroFilter.java:292)
	at org.apache.shiro.web.servlet.AbstractShiroFilter.doFilterInternal(AbstractShiroFilter.java:359)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: core/src/main/java/org/apache/shiro/mgt/AbstractRememberMeManager.java
- **Function**: convertBytesToPrincipals
- **Line Range**: 427-432
- **Column Range**: 1-5 (method declaration and body)

### Location 2 (root_cause) - Same as crash_site
- **Type**: root_cause
- **File Path**: core/src/main/java/org/apache/shiro/mgt/AbstractRememberMeManager.java
- **Function**: convertBytesToPrincipals
- **Line Range**: 427-432
- **Column Range**: 1-5

**Note**: The crash_site and root_cause are the same location because the vulnerable deserialization happens directly in the `convertBytesToPrincipals()` method at line 431 where `deserialize(bytes)` is called.

### Code Context

**AbstractRememberMeManager.java (lines 427-432):**
```java
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);
    }
    return deserialize(bytes);  // Line 431 - Unsafe deserialization
}
```

**AbstractRememberMeManager.java (lines 513-515) - deserialize method:**
```java
protected PrincipalCollection deserialize(byte[] serializedIdentity) {
    return getSerializer().deserialize(serializedIdentity);
}
```

**DefaultSerializer.java (lines 67-84) - actual deserialization:**
```java
public T deserialize(byte[] serialized) throws SerializationException {
    if (serialized == null) {
        String msg = "argument cannot be null.";
        throw new IllegalArgumentException(msg);
    }
    ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
    BufferedInputStream bis = new BufferedInputStream(bais);
    try {
        ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);
        @SuppressWarnings({"unchecked"})
        T deserialized = (T) ois.readObject();  // Line 77 - Unsafe readObject()
        ois.close();
        return deserialized;
    } catch (Exception e) {
        String msg = "Unable to deserialze argument byte array.";
        throw new SerializationException(msg, e);
    }
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-502** is the primary weakness, as the unsafe deserialization enables the command injection

## Vulnerability Description

This is **CVE-2016-4437**, a critical insecure deserialization vulnerability in Apache Shiro's "Remember Me" functionality that allows remote code execution.

### Attack Flow:
1. An attacker crafts a malicious serialized Java object (using tools like ysoserial)
2. The payload contains a deserialization gadget chain (e.g., using Apache Commons BeanUtils and XSLT TemplatesImpl)
3. The payload is Base64-encoded and sent in the `rememberMe` cookie
4. Apache Shiro's `AbstractRememberMeManager.getRememberedPrincipals()` retrieves the cookie data
5. The data is passed to `convertBytesToPrincipals()` which:
   - Optionally decrypts the data (if cipher is configured)
   - Calls `deserialize()` on the untrusted data
6. `DefaultSerializer.deserialize()` uses `ObjectInputStream.readObject()` without any validation
7. The deserialization triggers the gadget chain:
   - `PriorityQueue.readObject()` is called
   - This triggers `BeanComparator.compare()`
   - Which invokes `TemplatesImpl.getOutputProperties()`
   - Leading to arbitrary bytecode execution
   - Ultimately executing OS commands via `Runtime.exec()`

### Root Cause:
The vulnerability exists because Apache Shiro deserializes untrusted user-controlled data from the `rememberMe` cookie without proper validation. The `convertBytesToPrincipals()` method blindly deserializes the bytes using Java's native deserialization mechanism (`ObjectInputStream.readObject()`), which can trigger arbitrary code execution through deserialization gadget chains present in the classpath.

### Impact:
- **Remote Code Execution (RCE)**: Attackers can execute arbitrary system commands
- **Authentication Bypass**: Attackers can bypass authentication mechanisms
- **CVSS 3.1 Score**: 9.8 (CRITICAL)
- Listed in CISA's Known Exploited Vulnerabilities Catalog

## POV Analysis

The POV file (`pov_0.blob`) contains a serialized payload that exploits this vulnerability. Based on the stack trace, it uses:
- **Gadget Chain**: PriorityQueue → BeanComparator → TemplatesImpl → Runtime.exec()
- **Payload**: ysoserial-generated payload that executes OS commands
- **Delivery**: Sent as the `rememberMe` cookie value

The POV successfully demonstrates:
1. Deserialization of malicious object from cookie
2. Gadget chain activation through Java's readObject()
3. Code execution leading to OS command injection
4. Detection by Jazzer's security sanitizers (FuzzerSecurityIssueCritical)

## Patch Analysis

The patch file (`patch_0.diff`) completely disables the vulnerable deserialization:

```diff
--- a/core/src/main/java/org/apache/shiro/mgt/AbstractRememberMeManager.java
+++ b/core/src/main/java/org/apache/shiro/mgt/AbstractRememberMeManager.java
@@ -425,10 +425,8 @@
      * @return the de-serialized and possibly decrypted principals
      */
     protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
-        if (getCipherService() != null) {
-            bytes = decrypt(bytes);
-        }
-        return deserialize(bytes);
+        // Disabled to prevent unsafe deserialization of attacker-controlled data.
+        return null;
     }
```

### Patch Strategy:
The fix takes a conservative approach by completely disabling the "Remember Me" deserialization functionality rather than attempting to whitelist safe classes or implement other validation mechanisms. This eliminates the attack vector entirely but also removes the feature.

**Note**: The actual Apache Shiro 1.2.5 fix was more nuanced, involving proper encryption key management and validation, but this benchmark patch uses the most secure approach of complete feature removal.

## Recommendations

### For vuln.yaml Generation:
- **Vulnerability Name**: "Apache Shiro RememberMe Deserialization RCE"
- **Primary CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Secondary CWE**: CWE-78 (OS Command Injection)
- **Severity**: CRITICAL (CVSS 3.1: 9.8)
- **Origin**: 1-day
- **CVE**: CVE-2016-4437
- **Release Date**: 06/07/2016

### Location Details:
- **crash_site and root_cause**: Same location
  - File: `core/src/main/java/org/apache/shiro/mgt/AbstractRememberMeManager.java`
  - Function: `convertBytesToPrincipals`
  - Lines: 427-432
  - The vulnerable call is at line 431: `return deserialize(bytes);`