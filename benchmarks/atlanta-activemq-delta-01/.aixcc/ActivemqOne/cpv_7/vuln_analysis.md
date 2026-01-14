# Vulnerability Analysis for cpv_7

## Summary
- **CPV ID**: cpv_7
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution (Deserialization of Untrusted Data)
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://osv.dev/vulnerability/CVE-2023-46604
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Detection Message**: "Unrestricted class/object creation based on externally controlled data may allow remote code execution depending on available classes on the classpath."
- **Crash Location**: org.apache.activemq.openwire.v8.BaseDataStreamMarshaller:232
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: 2dcc0a2b81cca232

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
	at org.apache.activemq.openwire.v8.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
	at org.apache.activemq.openwire.v8.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
	at org.apache.activemq.openwire.v8.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-6 (method declaration)

### Code Context
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // MISSING VALIDATION: No check that clazz is assignable to Throwable
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java
- **Function**: looseUnmarsalThrowable
- **Line Range**: 511-547
- **Column Range**: 1-6

The crash is detected by Jazzer when the arbitrary class is instantiated at line 232 in `createThrowable`, but the vulnerability originates from the missing validation before class instantiation.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-913**: Improper Control of Dynamically-Managed Code Resources

## Vulnerability Description

This is CVE-2023-46604, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability allows a remote attacker with network access to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol.

### Root Cause
The `createThrowable` method in `BaseDataStreamMarshaller` accepts an arbitrary class name from untrusted network data and instantiates it using reflection without validating that the class is actually a subclass of `Throwable`. This allows an attacker to instantiate any class on the classpath with a String constructor.

### Attack Vector
1. An attacker sends a specially crafted OpenWire protocol message containing an `ExceptionResponse` object
2. The `ExceptionResponseMarshaller.looseUnmarshal` method calls `looseUnmarsalThrowable`
3. `looseUnmarsalThrowable` extracts the class name and message from untrusted data and passes them to `createThrowable`
4. `createThrowable` uses `Class.forName()` to load the attacker-controlled class name
5. Without validation, it instantiates the class using reflection with the attacker-controlled message parameter
6. Known exploits use `ClassPathXmlApplicationContext` to load malicious XML configuration files from remote locations

### Impact
- **CVSS Score**: 9.8/10.0 (CRITICAL)
- **Attack Vector**: Network (remote)
- **Privileges Required**: None
- **User Interaction**: None
- **Confidentiality Impact**: High
- **Integrity Impact**: High
- **Availability Impact**: High

This vulnerability has been actively exploited in the wild to deploy ransomware and cryptominers. It appears in CISA's Known Exploited Vulnerabilities Catalog.

## POV Analysis
The POV file (`pov_0.blob`) contains a crafted OpenWire protocol message that triggers the vulnerability by specifying a malicious class name (likely `jaz.Zer` based on the stack trace, which is Jazzer's security issue reporter) to be instantiated instead of a legitimate Throwable class.

## Patch Analysis

The patch implements proper validation to prevent arbitrary class instantiation:

### Added Validation Method (OpenWireUtil.java)
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

### Applied Validation (BaseDataStreamMarshaller.java)
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The fix ensures that only classes that extend `Throwable` can be instantiated, preventing the exploitation of arbitrary class instantiation for remote code execution.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-913]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Arbitrary Class Instantiation Remote Code Execution
- **Severity**: Critical (CVSS 9.8-10.0)
- **Affected Versions**: 
  - Apache ActiveMQ < 5.15.16
  - 5.16.0 - 5.16.6
  - 5.17.0 - 5.17.5
  - 5.18.0 - 5.18.2
- **Fixed Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3