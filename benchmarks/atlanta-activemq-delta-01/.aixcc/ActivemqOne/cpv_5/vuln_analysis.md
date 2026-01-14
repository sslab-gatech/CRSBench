# Vulnerability Analysis for cpv_5

## Summary
- **CPV ID**: cpv_5
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java:233
- **Vulnerable Function**: `createThrowable`
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
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: N/A (entire function)

### Code Context
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // MISSING VALIDATION HERE - any class can be loaded, not just Throwable subclasses
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The vulnerability is at **line 231** where `Class.forName(className, ...)` is called with an attacker-controlled `className` parameter without validating that the loaded class is actually a `Throwable` subclass. This allows arbitrary class instantiation.

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v6/BaseDataStreamMarshaller.java
- **Function**: looseUnmarsalThrowable
- **Line Range**: 512-545
- **Column Range**: N/A

The crash occurs when `createThrowable` is invoked from line 517 during deserialization:
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);  // attacker-controlled class name
        String message = looseUnmarshalString(dataIn); // attacker-controlled message
        Throwable o = createThrowable(clazz, message); // vulnerable call
        ...
    }
    ...
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data - The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') - The application uses external input to determine which class or code to use.
- **CWE-94**: Improper Control of Generation of Code ('Code Injection') - The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended control flow.

## Vulnerability Description

**CVE-2023-46604** is a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability exists in the `createThrowable` method of the `BaseDataStreamMarshaller` class, which is used during the deserialization of `ExceptionResponse` objects.

**Root Cause**: The `createThrowable` method accepts an arbitrary class name from untrusted network input and uses `Class.forName()` to load it, followed by reflective instantiation via `Constructor.newInstance()`. Critically, **there is no validation to ensure the loaded class is actually a subclass of `Throwable`**. This allows an attacker to instantiate any class on the classpath that has a constructor accepting a single `String` parameter.

**Attack Vector**: An attacker with network access to an ActiveMQ broker's OpenWire port (typically 61616) can send a malicious `ExceptionResponse` message containing:
1. An arbitrary class name (e.g., a malicious class or gadget class like `jaz.Zer`)
2. An arbitrary string parameter to pass to the constructor

When the broker deserializes this message, it will:
1. Extract the attacker-controlled class name and message
2. Call `createThrowable(className, message)`
3. Load and instantiate the arbitrary class with the provided string argument
4. Execute any code in the class constructor or initializers

**Impact**: This vulnerability enables complete remote code execution without authentication. An attacker can execute arbitrary commands, install malware, steal data, or pivot to other systems. The vulnerability has a **CVSS score of 10.0 (Critical)** and has been actively exploited in the wild to deploy ransomware and cryptocurrency miners.

## POV Analysis

The POV file (39 bytes) contains a crafted OpenWire message that triggers the vulnerability. Based on the hexdump:

```
00000000  06 00 00 00 22 1f 00 00  00 00 00 00 00 00 00 01
00000010  01 00 07 6a 61 7a 2e 5a  65 72 01 00 0a 68 65 6c
00000020  6c 6f 77 6f 72 6c 64
```

The POV contains:
- OpenWire message header with type code (06 = ExceptionResponse)
- Class name: `jaz.Zer` (a Jazzer hook class that detects and reports security issues)
- Message string: `helloworld`

When deserialized, this causes the instantiation of the `jaz.Zer` class (which is not a Throwable), triggering Jazzer's detection mechanism that identifies this as a Remote Code Execution vulnerability.

## Patch Analysis

The fix adds validation to ensure only legitimate `Throwable` subclasses can be instantiated:

**1. New validation method in `OpenWireUtil.java`:**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**2. Validation added to `BaseDataStreamMarshaller.createThrowable()` at line 232:**
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

This validation ensures that only classes that extend `Throwable` can be loaded and instantiated, preventing arbitrary code execution. The fix was applied across multiple OpenWire protocol versions (v1-v12) in the patched versions 5.15.16, 5.16.7, 5.17.6, and 5.18.3.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-94]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Unsafe Deserialization Remote Code Execution
- **Severity**: Critical (CVSS 10.0)
- **Mitigation**: Upgrade to Apache ActiveMQ versions 5.15.16, 5.16.7, 5.17.6, or 5.18.3 or later. If immediate patching is not possible, restrict network access to the OpenWire port (61616) to trusted sources only.