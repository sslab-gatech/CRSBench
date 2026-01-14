# Vulnerability Analysis for cpv_7

## Summary
- **CPV ID**: cpv_7
- **Harness**: ActivemqVariantOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **CVE**: CVE-2023-46604
- **Release Date**: 10/27/2023
- **CVSS Score**: 10.0 (CRITICAL)
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Error Message**: "Unrestricted class/object creation based on externally controlled data may allow remote code execution depending on available classes on the classpath."
- **Crash Location**: `BaseDataStreamMarshaller.java:232` (in `createThrowable` method)
- **Vulnerable Function**: `createThrowable`
- **DEDUP Token**: `2dcc0a2b81cca232`

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
	at org.apache.activemq.openwire.v8.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
	at org.apache.activemq.openwire.v8.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
	at org.apache.activemq.openwire.v8.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
DEDUP_TOKEN: 2dcc0a2b81cca232
```

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: crash_site, root_cause
- **File Path**: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
- **Function**: `createThrowable`
- **Line Range**: 228-239
- **Column Range**: N/A (Java - not applicable)

### Code Context
```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // VULNERABILITY: No validation that clazz is a Throwable subclass
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The vulnerability exists at line 231-233 where:
1. Line 231: An arbitrary class is loaded via `Class.forName()` using attacker-controlled `className`
2. Line 232: A constructor is obtained without validating that the class extends `Throwable`
3. Line 233: The arbitrary class is instantiated with attacker-controlled `message` parameter

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability allows an attacker with network access to a broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol.

### Root Cause

The `createThrowable` method in `BaseDataStreamMarshaller.java` (line 228) is designed to deserialize exception objects from OpenWire protocol messages. However, it fails to validate that the deserialized class actually extends `Throwable` before instantiation. This allows an attacker to:

1. Send a malicious OpenWire packet containing an `ExceptionResponse` object
2. Specify an arbitrary class name (e.g., `jaz.Zer` in the POV, or more dangerously `org.springframework.context.support.ClassPathXmlApplicationContext`)
3. Provide a malicious string parameter (e.g., URL to remote XML configuration)
4. Trigger instantiation of arbitrary classes with attacker-controlled constructor parameters

### Attack Vector

The vulnerability is triggered when:
1. An attacker sends an OpenWire message to the ActiveMQ broker (default port 61616)
2. The message contains an `ExceptionResponse` with a crafted class name
3. The `ExceptionResponseMarshaller.looseUnmarshal()` method calls `looseUnmarshalThrowable()`
4. This invokes `createThrowable()` with the attacker-controlled class name
5. Any class on the classpath can be instantiated, including dangerous classes like `ClassPathXmlApplicationContext`

### Impact

- **Remote Code Execution**: Attackers can execute arbitrary code on the target system
- **Complete System Compromise**: Full control over the ActiveMQ broker or client
- **CVSS Score**: 10.0 (CRITICAL) - Maximum severity
- **Listed in CISA KEV**: Known to be actively exploited in the wild

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted OpenWire message that attempts to instantiate the class `jaz.Zer`:

```
Hex dump: 0800 0000 221f 0000 0000 0000 0000 0001
          0100 076a 617a 2e5a 6572 0100 0a68 656c
          6c6f 776f 726c 64

Class name: "jaz.Zer" (7 bytes)
Message: "helloworld" (10 bytes)
```

The class `jaz.Zer` is a Jazzer-provided class that reports security findings. When the vulnerable code attempts to instantiate this class (which is not a `Throwable`), it triggers the security detection and demonstrates the arbitrary class instantiation vulnerability.

In real-world attacks, attackers use `org.springframework.context.support.ClassPathXmlApplicationContext` with a URL pointing to a malicious XML configuration file to achieve remote code execution.

## Patch Analysis

The fix adds validation to ensure only `Throwable` subclasses can be instantiated:

### Patch Location 1: OpenWireUtil.java (NEW FILE)
- **File**: `activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireUtil.java`
- **Change**: Added new validation method `validateIsThrowable()`

```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

### Patch Location 2: BaseDataStreamMarshaller.java (MODIFIED)
- **File**: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
- **Change**: Added validation call after loading the class (line 232)

```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // ← NEW: Validation added
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The patch ensures that only classes that are subclasses of `Throwable` can be instantiated, preventing arbitrary class instantiation and remote code execution.

## Affected Versions

- Apache ActiveMQ before 5.15.16
- Versions 5.16.0 through 5.16.6
- Versions 5.17.0 through 5.17.5
- Versions 5.18.0 through 5.18.2

## Patched Versions

- 5.15.16 (final 5.15.x release)
- 5.16.7 (final 5.16.x release)
- 5.17.6
- 5.18.3
- 6.0.0

## Recommendations

**For vuln.yaml generation:**
- **Vulnerability Name**: "Apache ActiveMQ OpenWire Protocol Remote Code Execution"
- **CWEs**: [CWE-502, CWE-470, CWE-94]
- **Origin**: 1-day
- **CVE**: CVE-2023-46604
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/news/cve-2023-46604

**Locations:**
- **crash_site**: 
  - File: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
  - Function: `createThrowable`
  - Lines: 231-233 (the reflection-based class instantiation)
  
- **root_cause**: Same as crash_site (the vulnerability and crash occur at the same location - the missing validation before class instantiation)