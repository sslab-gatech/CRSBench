# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://osv.dev/vulnerability/BIT-activemq-2023-46604
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java:233
- **Vulnerable Function**: `createThrowable`
- **DEDUP Token**: 8bbb9ac0a72618f2

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
	at java.base/java.lang.reflect.Constructor.newInstanceWithCaller(Constructor.java:499)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:480)
	at org.apache.activemq.openwire.v2.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v2.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v2.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:114)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java
- **Function**: `createThrowable`
- **Line Range**: 229-239
- **Column Range**: 1-6

### Code Context (Vulnerable Code - Before Patch)
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

The vulnerability exists at **line 231** where `Class.forName()` loads an arbitrary class without validation, and at **line 233** where `constructor.newInstance()` instantiates that class without verifying it's a Throwable subclass.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-094**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol implementation. The vulnerability allows an attacker with network access to execute arbitrary code by manipulating serialized class types in the OpenWire protocol.

### Root Cause
The `createThrowable` method in `BaseDataStreamMarshaller.java` accepts an externally-controlled class name and instantiates it using reflection without validating that the class is actually a subclass of `Throwable`. This allows an attacker to:

1. Send a malicious OpenWire `ExceptionResponse` message
2. Specify an arbitrary class name (e.g., `jaz.Zer` or `org.springframework.context.support.ClassPathXmlApplicationContext`)
3. Provide a constructor argument (the `message` parameter)
4. Have the system instantiate that class with the attacker-controlled argument

### Attack Vector
The published exploit uses `ClassPathXmlApplicationContext` from Spring Framework to load a malicious XML configuration file from a remote URL, which can then execute arbitrary system commands via `ProcessBuilder`.

### Impact
- **Severity**: CVSS 9.8 (Critical) / 10.0 (Perfect score in some assessments)
- **Remote Code Execution**: Complete system compromise
- **No Authentication Required**: Attack can be performed over the network without credentials
- **Active Exploitation**: Used in real-world ransomware attacks (HelloKitty) and cryptominer deployments

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted OpenWire message that demonstrates the vulnerability. Hex dump analysis shows:

```
00000000: 0200 0000 221f 0000 0000 0000 0000 0001  ...."...........
00000010: 0100 076a 617a 2e5a 6572 0100 0a68 656c  ...jaz.Zer...hel
00000020: 6c6f776f 726c 64                        loworld
```

The POV specifies:
- **Class name**: `jaz.Zer` (Jazzer's security detection class - bytes `6a 61 7a 2e 5a 65 72`)
- **Constructor argument**: `helloworld` (bytes `68 65 6c 6c 6f 77 6f 72 6c 64`)

This triggers the Jazzer security hook that detects unsafe class instantiation, demonstrating that arbitrary classes can be loaded and instantiated.

## Patch Analysis

The patch introduces a validation function to prevent arbitrary class instantiation:

### Patch Location 1: New Validation Method
- **File**: activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireUtil.java
- **Lines Added**: 9-19 (new method)

```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

### Patch Location 2: Validation Call
- **File**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java
- **Line Modified**: 231 (added line 232)

```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
```

The patch ensures that only classes that extend `Throwable` (exceptions and errors) can be instantiated, preventing arbitrary code execution via classes like `ClassPathXmlApplicationContext`.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-094]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Unsafe Deserialization Remote Code Execution
- **Affected Versions**: Apache ActiveMQ 5.18.0 before 5.18.3, 5.17.0 before 5.17.6, 5.16.0 before 5.16.7, and before 5.15.16
- **Fixed Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3