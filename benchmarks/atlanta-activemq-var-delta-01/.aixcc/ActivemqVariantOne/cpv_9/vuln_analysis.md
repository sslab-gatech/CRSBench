# Vulnerability Analysis for cpv_9

## Summary
- **CPV ID**: cpv_9
- **Harness**: ActivemqVariantOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org.apache.activemq.openwire.v10.BaseDataStreamMarshaller.java:233
- **Vulnerable Function**: `createThrowable`
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
- **Line Range**: 233-233
- **Column Range**: 1-80

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v10/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 232-232
- **Column Range**: 1-80

### Code Context

**Vulnerable code (before patch):**
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

The vulnerability exists at line 232 where `Class.forName()` is called with an attacker-controlled `className` parameter, followed by line 233 where the class is instantiated. There is no validation that the loaded class is actually a `Throwable` subclass before instantiation.

**Patched code (after fix):**
```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- Added validation
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The patch adds a validation method in `OpenWireUtil.validateIsThrowable()`:
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-184**: Incomplete List of Disallowed Inputs

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability allows a remote attacker with network access to a broker or client to execute arbitrary code by manipulating serialized class types.

### Root Cause

The `createThrowable()` method in `BaseDataStreamMarshaller` deserializes exception objects from OpenWire protocol messages. The method accepts two externally-controlled parameters:
1. `className` - The fully qualified class name to instantiate
2. `message` - A string parameter passed to the class constructor

The vulnerability arises because:
1. The method uses `Class.forName()` to load **any arbitrary class** on the classpath without proper validation
2. There is only a weak check that the class name starts with "j", which is insufficient
3. The loaded class is not validated to be a `Throwable` subclass before instantiation
4. The method then instantiates this class with a constructor that takes a single `String` parameter

### Attack Vector

An attacker can craft a malicious OpenWire message containing an `ExceptionResponse` object with a carefully chosen class name (e.g., `jaz.Zer` as seen in the POV, or `org.springframework.context.support.ClassPathXmlApplicationContext` in real-world exploits). When the message is deserialized:

1. The `OpenWireFormat.doUnmarshal()` method reads the message
2. It delegates to `ExceptionResponseMarshaller.looseUnmarshal()`
3. Which calls `BaseDataStreamMarshaller.looseUnmarsalThrowable()`
4. Which finally calls `createThrowable()` with attacker-controlled class name and parameter

The attacker can instantiate any class on the classpath that has a constructor accepting a single `String` parameter. Common exploitation uses Spring's `ClassPathXmlApplicationContext` which can load XML configuration files from remote URLs, leading to remote code execution.

### Impact

- **Remote Code Execution**: Attackers can execute arbitrary commands on the target system
- **No Authentication Required**: The vulnerability can be exploited by any network entity with access to the OpenWire port (default: 61616)
- **CVSS Score**: 10.0 (Critical) - Perfect score from Apache Software Foundation
- **Active Exploitation**: This vulnerability is actively exploited in the wild, including by HelloKitty ransomware

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted OpenWire message with:
- A class name: `jaz.Zer` (a Jazzer security issue reporting class)
- A message parameter: `helloworld`

When deserialized, this instantiates the `jaz.Zer` class which is designed to detect and report unsafe deserialization as a security issue. The POV successfully triggers the vulnerability by:
1. Passing the weak "j" prefix check (class name starts with "j")
2. Loading the `jaz.Zer` class via reflection
3. Instantiating it, which triggers the security detection mechanism

## Patch Analysis

The patch introduces a security validation layer:

1. **New validation method** in `OpenWireUtil.java`:
   - `validateIsThrowable(Class<?> clazz)` checks if the loaded class is assignable to `Throwable`
   - Throws `IllegalArgumentException` if validation fails

2. **Integration point** in `BaseDataStreamMarshaller.java`:
   - Calls `OpenWireUtil.validateIsThrowable(clazz)` immediately after `Class.forName()`
   - Ensures only legitimate `Throwable` subclasses can be instantiated
   - Prevents instantiation of arbitrary classes like `ClassPathXmlApplicationContext`

The patch is applied to all vulnerable OpenWire protocol versions (v10, v11, and others).

## Recommendations

- **CWEs**: CWE-502 (primary), CWE-470, CWE-184
- **Vulnerability Name**: "Apache ActiveMQ OpenWire Unsafe Deserialization RCE"
- **Severity**: Critical (CVSS 10.0)
- **Affected Versions**: ActiveMQ < 5.15.16, 5.16.0-5.16.6, 5.17.0-5.17.5, 5.18.0-5.18.2
- **Patched Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3, 6.0.0

---

**Analysis Complete**: This vulnerability represents a classic unsafe deserialization flaw where insufficient input validation on class names allows arbitrary code execution through reflection-based instantiation. The patch correctly addresses the root cause by adding type validation before object instantiation.