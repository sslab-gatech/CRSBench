# Vulnerability Analysis for cpv_9

## Summary
- **CPV ID**: cpv_9
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution (RCE) via Insecure Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: BaseDataStreamMarshaller.java:233 (createThrowable method)
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: 4d056d106da91665

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
	at org.apache.activemq.openwire.v10.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v10.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v10.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v10/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-80

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v10/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-80

Note: The crash_site and root_cause are the same in this vulnerability. The vulnerable code is in the `createThrowable` method which directly instantiates arbitrary classes without validation.

### Code Context (Vulnerable Code)
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // VULNERABILITY: No validation that clazz is actually a Throwable
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The vulnerability exists at line 231 where `Class.forName()` loads an arbitrary class specified by the attacker, and line 233 where that class is instantiated without validating that it's actually a `Throwable` type. This allows an attacker to instantiate any class on the classpath with a single String constructor parameter.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-913**: Improper Control of Dynamically-Managed Code Resources

## Vulnerability Description

**CVE-2023-46604** is a critical Remote Code Execution (RCE) vulnerability in Apache ActiveMQ with a CVSS score of 10.0. The vulnerability exists in the Java OpenWire protocol marshaller, specifically in the `BaseDataStreamMarshaller.createThrowable()` method.

### Root Cause
The `createThrowable()` method accepts an arbitrary class name from untrusted network data and uses reflection to instantiate it without validating that the class is actually a `Throwable` type. This insecure deserialization allows a remote attacker with network access to an OpenWire broker or client to instantiate any class on the Java classpath with a single attacker-controlled String parameter.

### Attack Vector
1. An attacker sends a malicious OpenWire protocol message containing an `ExceptionResponse` object
2. The `ExceptionResponseMarshaller.looseUnmarshal()` method processes this message
3. It calls `looseUnmarshalThrowable()` which extracts the attacker-supplied class name and message
4. The `createThrowable()` method uses `Class.forName()` to load the specified class
5. Without validation, it instantiates the class via reflection with the attacker-controlled message string
6. An attacker can instantiate dangerous classes like `org.springframework.context.support.ClassPathXmlApplicationContext` (part of Spring framework available in ActiveMQ) to achieve arbitrary code execution

### Impact
- **Remote Code Execution**: Attackers can execute arbitrary shell commands on the target system
- **Complete System Compromise**: With RCE, attackers gain full control over the ActiveMQ broker or client
- **Lateral Movement**: Compromised systems can be used as pivot points for further attacks
- **Data Breach**: Access to sensitive message queue data and connected systems

## POV Analysis

The POV file (`pov_0.blob`, 39 bytes) contains a crafted OpenWire message that triggers the vulnerability:

```
Hex dump:
00000000: 0a00 0000 221f 0000 0000 0000 0000 0001  ...."...........
00000010: 0100 076a 617a 2e5a 6572 0100 0a68 656c  ...jaz.Zer...hel
00000020: 6c6f776f 726c 64                        loworld
```

The POV contains:
- An ExceptionResponse message (opcode 0x1f at offset 0x04)
- Class name: `jaz.Zer` (at offset 0x10-0x16) - This is a test class used by Jazzer fuzzer to detect the vulnerability
- Message: `helloworld` (at offset 0x1a-0x26)

The Jazzer security hook detects when the `jaz.Zer` class is instantiated via reflection, indicating unrestricted class instantiation which is a security vulnerability. The actual exploit in the wild would use classes like `ClassPathXmlApplicationContext` instead of `jaz.Zer`.

## Patch Analysis

The patch adds validation to prevent arbitrary class instantiation:

### File 1: OpenWireUtil.java (New validation method)
```java
/**
 * Verify that the provided class extends {@link Throwable} and throw an
 * {@link IllegalArgumentException} if it does not.
 *
 * @param clazz
 */
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

### File 2: v10/BaseDataStreamMarshaller.java (Apply validation)
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    }
```

**How the fix works:**
1. After loading the class with `Class.forName()`, the code now calls `OpenWireUtil.validateIsThrowable(clazz)`
2. This method checks if the loaded class is assignable to `Throwable` using `Throwable.class.isAssignableFrom(clazz)`
3. If the class is not a valid `Throwable` (like `ClassPathXmlApplicationContext`), it throws an `IllegalArgumentException`
4. This prevents instantiation of arbitrary classes, limiting the attack surface to only legitimate exception classes

The fix must be applied to all versions of BaseDataStreamMarshaller (v1, v9, v10, v11, v12, and legacy versions v2-v8) as they all contain the same vulnerable pattern.

## Affected Versions
- Apache ActiveMQ < 5.15.16
- Apache ActiveMQ 5.16.0 - 5.16.6
- Apache ActiveMQ 5.17.0 - 5.17.5
- Apache ActiveMQ 5.18.0 - 5.18.2

## Fixed Versions
- Apache ActiveMQ 5.15.16
- Apache ActiveMQ 5.16.7
- Apache ActiveMQ 5.17.6
- Apache ActiveMQ 5.18.3
- Apache ActiveMQ 6.0.0

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-913]
- **Vulnerability name**: Remote Code Execution via Insecure Deserialization in OpenWire Protocol
- **Severity**: Critical (CVSS 10.0)
- **Exploitability**: Actively exploited in the wild, including by ransomware groups