# Vulnerability Analysis for cpv_8

## Summary
- **CPV ID**: cpv_8
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Arbitrary Class Instantiation
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog (Added 11/02/2023)

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Detection**: Jazzer security hook detected unrestricted class/object creation based on externally controlled data
- **Vulnerable Function**: `createThrowable` in `BaseDataStreamMarshaller`
- **Call Chain**: 
  - `ExceptionResponseMarshaller.looseUnmarshal` (line 113)
  - `BaseDataStreamMarshaller.looseUnmarsalThrowable` (line 516)
  - `BaseDataStreamMarshaller.createThrowable` (line 232)
- **DEDUP Token**: c6ea0dba7e194a4a

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
Unrestricted class/object creation based on externally controlled data may allow
remote code execution depending on available classes on the classpath.
	at jaz.Zer.reportFinding(Zer.java:110)
	at jaz.Zer.reportFindingIfEnabled(Zer.java:105)
	at jaz.Zer.<init>(Zer.java:82)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
	at java.base/jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:480)
	at org.apache.activemq.openwire.v9.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
	at org.apache.activemq.openwire.v9.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
	at org.apache.activemq.openwire.v9.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v9/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: Not specified (Java stack trace shows line 232)

### Location 2 (root_cause) - Same as crash_site
The root cause and crash site are the same location. The vulnerable code is in the `createThrowable` method where arbitrary class instantiation occurs without validation.

### Code Context

**Vulnerable code (pre-patch):**
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

**Where it's called from:**
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);
        String message = looseUnmarshalString(dataIn);
        Throwable o = createThrowable(clazz, message);  // Line 516 - vulnerable call
        // ... rest of unmarshalling
    }
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is CVE-2023-46604, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol implementation. The vulnerability exists in the `createThrowable` method of `BaseDataStreamMarshaller`, which is called during the deserialization of `ExceptionResponse` objects.

**Attack Vector:**
1. An attacker sends a malicious OpenWire `ExceptionResponse` message to an ActiveMQ broker or client
2. The `ExceptionResponseMarshaller.looseUnmarshal` method processes the message
3. It extracts attacker-controlled `className` and `message` strings from the serialized data
4. These are passed to `createThrowable`, which uses `Class.forName()` to load the specified class
5. The method then instantiates the class without validating it extends `Throwable`
6. An attacker can specify arbitrary classes on the classpath (e.g., `org.springframework.context.support.ClassPathXmlApplicationContext`)
7. When instantiated with a malicious URL as the message parameter, the class can fetch and execute remote code

**Impact:**
- Complete remote code execution with the privileges of the ActiveMQ server
- No authentication required (unauthenticated RCE)
- Can be exploited to deploy ransomware, cryptominers, rootkits, or establish persistent backdoors
- Listed in CISA's Known Exploited Vulnerabilities Catalog

**Severity:**
- CVSS 3.1 Base Score: 10.0 (Critical) per Apache
- CVSS 3.1 Base Score: 9.8 (Critical) per NIST
- Actively exploited in the wild

## POV Analysis
The POV file (`pov_0.blob`) is a 39-byte binary file containing a crafted OpenWire message that triggers the vulnerability. It exploits the lack of validation in the `createThrowable` method to instantiate an arbitrary class detected by Jazzer's deserialization hooks.

## Patch Analysis

The patch introduces validation to ensure only `Throwable` classes can be instantiated:

**File 1: OpenWireUtil.java** - New validation method added:
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**File 2: BaseDataStreamMarshaller.java** - Validation added to createThrowable:
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW VALIDATION
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

**Fix Strategy:**
The patch adds a type safety check before instantiation. After loading the class with `Class.forName()`, it validates that the class is assignable to `Throwable`. This prevents attackers from instantiating arbitrary classes like `ClassPathXmlApplicationContext` or other dangerous classes that don't extend `Throwable`.

## Recommendations

**Suggested CWEs:** [CWE-502, CWE-470, CWE-94]

**Vulnerability Name:** Apache ActiveMQ OpenWire Protocol Arbitrary Class Instantiation RCE (CVE-2023-46604)

**Additional Context:**
- This vulnerability affects multiple ActiveMQ versions: 5.18.0-5.18.2, 5.17.0-5.17.5, 5.16.0-5.16.6, and all versions before 5.15.16
- Fixed in versions: 5.15.16, 5.16.7, 5.17.6, and 5.18.3
- The OpenWire protocol connector listens on TCP port 61616 by default and is enabled by default
- The same vulnerability pattern exists across multiple OpenWire protocol versions (v1-v12) in the codebase