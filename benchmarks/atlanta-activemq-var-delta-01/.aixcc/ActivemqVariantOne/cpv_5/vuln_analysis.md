# Vulnerability Analysis for cpv_5

## Summary
- **CPV ID**: cpv_5
- **Harness**: ActivemqVariantOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Detection**: Jazzer security sanitizer detected unrestricted class/object creation based on externally controlled data
- **Vulnerable Function**: `createThrowable` (called via `looseUnmarsalThrowable`)
- **DEDUP Token**: 7e9cd1a2cc89bfdf

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
	at org.apache.activemq.openwire.v6.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v6.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v6.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java
- **Function**: `createThrowable`
- **Line Range**: 232-234
- **Column Range**: 13-101 (line 232), 13-84 (line 233), 20-70 (line 234)

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java
- **Function**: `createThrowable`
- **Line Range**: 232-234
- **Column Range**: 13-101 (line 232), 13-84 (line 233), 20-70 (line 234)

**Note**: For this vulnerability, crash_site and root_cause are the same location. The vulnerability is in the `createThrowable` method which fails to validate that the loaded class is actually a Throwable subclass before instantiating it.

### Code Context

**Vulnerable code** (activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java:229-240):
```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
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

**Entry point** (activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java:513-518):
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);
        String message = looseUnmarshalString(dataIn);
        Throwable o = createThrowable(clazz, message);
        // ... rest of method
```

**Call site from ExceptionResponseMarshaller** (activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/ExceptionResponseMarshaller.java:113):
```java
info.setException((java.lang.Throwable) looseUnmarsalThrowable(wireFormat, dataIn));
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol implementation. The vulnerability has a CVSS score of 10.0 (CRITICAL) and has been actively exploited in the wild.

### Root Cause

The `createThrowable` method in `BaseDataStreamMarshaller` accepts externally-controlled class names from deserialized OpenWire protocol data without validating that the specified class is actually a subclass of `Throwable`. The method performs minimal validation (only checking if the class name starts with "j"), then uses reflection to:

1. Load an arbitrary class via `Class.forName(className, ...)`
2. Get a constructor that accepts a String parameter
3. Instantiate the class via `constructor.newInstance(...)`

This allows an attacker to instantiate any class on the classpath that has a String constructor, not just Throwable subclasses, leading to arbitrary code execution.

### Attack Vector

An attacker with network access to an ActiveMQ broker can:
1. Connect to the OpenWire protocol port (default 61616)
2. Send a malicious `ExceptionResponse` message containing:
   - An arbitrary class name (e.g., a class that executes code in its constructor)
   - A string parameter to pass to the constructor
3. When the broker unmarshals the message, it instantiates the attacker-controlled class
4. If the class executes code in its constructor, arbitrary code execution is achieved

### Impact

- **Remote Code Execution**: Complete compromise of the ActiveMQ broker
- **Data Breach**: Access to all messages and sensitive data
- **Lateral Movement**: Potential pivot point to internal network
- **Service Disruption**: DoS or ransomware attacks

This vulnerability has been exploited by multiple threat actors including ransomware groups (HelloKitty) and cryptominers (Kinsing).

## POV Analysis

The POV file triggers the vulnerability by sending crafted OpenWire protocol data that includes an `ExceptionResponse` with a malicious class name. The Jazzer security sanitizer detected the attempted instantiation of the `jaz.Zer` class (a Jazzer hook used for testing), which is not a Throwable subclass, demonstrating the lack of type validation.

## Patch Analysis

The patch adds validation to ensure that only actual Throwable subclasses can be instantiated:

**New validation method** (activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireUtil.java):
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**Applied in createThrowable** (activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java:232):
```java
Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW VALIDATION
Constructor constructor = clazz.getConstructor(new Class[] {String.class});
```

This validation ensures that the loaded class actually extends `Throwable` before attempting to instantiate it, preventing arbitrary class instantiation.

## Recommendations

- **Suggested CWEs**: [CWE-502, CWE-470, CWE-94]
- **Vulnerability name**: Apache ActiveMQ OpenWire Unsafe Deserialization RCE
- **Severity**: CRITICAL (CVSS 10.0)
- **Affected Versions**: 
  - Apache ActiveMQ < 5.15.16
  - 5.16.0 - 5.16.6
  - 5.17.0 - 5.17.5
  - 5.18.0 - 5.18.2
- **Fixed Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3+