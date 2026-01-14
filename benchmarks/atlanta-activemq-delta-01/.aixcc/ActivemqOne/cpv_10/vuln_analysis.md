# Vulnerability Analysis for cpv_10

## Summary
- **CPV ID**: cpv_10
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Unrestricted Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: BaseDataStreamMarshaller.java:232 (in createThrowable method)
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: f695adcbca5fdb20

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
	at org.apache.activemq.openwire.v11.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
	at org.apache.activemq.openwire.v11.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
	at org.apache.activemq.openwire.v11.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-6 (entire method)

### Location 2 (root_cause) - Same as crash_site
The root cause and crash site are the same location. The vulnerability exists in the `createThrowable` method where arbitrary class names from untrusted input are instantiated without validation.

### Code Context
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // MISSING: Validation that clazz extends Throwable
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The vulnerable code accepts an arbitrary `className` from the deserialized OpenWire protocol data and uses reflection to instantiate it without verifying that the class actually extends `Throwable`. This allows an attacker to instantiate any class on the classpath with a single string parameter.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-20**: Improper Input Validation
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

CVE-2023-46604 is a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability allows a remote attacker with network access to a Java-based OpenWire broker or client to execute arbitrary code by manipulating serialized class types in the OpenWire protocol.

**Attack Mechanism:**

1. An attacker connects to the OpenWire port (typically 61616)
2. The attacker sends an OpenWire packet with data type 31 (EXCEPTION_RESPONSE)
3. During unmarshalling of the ExceptionResponse, the `BaseDataStreamMarshaller.looseUnmarsalThrowable` method is called
4. This method calls `createThrowable` with an attacker-controlled class name and message string
5. The `createThrowable` method uses `Class.forName()` to load the attacker-specified class
6. **Critical Flaw**: No validation is performed to ensure the class extends `Throwable`
7. The code uses reflection to instantiate the arbitrary class with the attacker-controlled string parameter
8. An attacker can instantiate dangerous classes like `org.springframework.context.support.ClassPathXmlApplicationContext`, which loads Spring configuration from a URL, enabling remote code execution

**Impact:**
- Complete system compromise via remote code execution
- No authentication required (network access only)
- CVSS Score: 10.0 CRITICAL (CNA) / 9.8 CRITICAL (NIST)

## POV Analysis

The POV file (`pov_0.blob`) is a 39-byte crafted OpenWire protocol message that triggers the vulnerability by sending an ExceptionResponse with a malicious class name that can be instantiated to achieve code execution. The Jazzer fuzzer's deserialization hooks detect this as a high-severity security issue.

## Patch Analysis

The patch adds a validation method `validateIsThrowable` in `OpenWireUtil.java`:

```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

This method is then called in `BaseDataStreamMarshaller.createThrowable` immediately after loading the class:

```java
Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added
Constructor constructor = clazz.getConstructor(new Class[] {String.class});
```

This fix ensures that only classes that actually extend `Throwable` can be instantiated, preventing the instantiation of arbitrary malicious classes like `ClassPathXmlApplicationContext`.

## Recommendations

- **Suggested CWEs**: [CWE-502, CWE-20, CWE-94]
- **Vulnerability Name**: "OpenWire Protocol Arbitrary Class Instantiation RCE"
- **Severity**: CRITICAL (CVSS 10.0)
- **Affected Versions**: Apache ActiveMQ < 5.15.16, 5.16.0-5.16.6, 5.17.0-5.17.5, 5.18.0-5.18.2
- **Fixed Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3