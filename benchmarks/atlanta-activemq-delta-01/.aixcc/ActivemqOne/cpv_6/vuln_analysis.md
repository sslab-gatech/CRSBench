# Vulnerability Analysis for cpv_6

## Summary
- **CPV ID**: cpv_6
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Deserialization of Untrusted Data
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssuehigh: Remote Code Execution
- **Crash Location**: BaseDataStreamMarshaller.java:232 (createThrowable method)
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: df61588f57eb74f6

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
	at org.apache.activemq.openwire.v7.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
	at org.apache.activemq.openwire.v7.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
	at org.apache.activemq.openwire.v7.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v7/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-80

### Location 2 (root_cause - same as crash_site)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v7/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-80

### Code Context

**Vulnerable code in BaseDataStreamMarshaller.java (lines 228-238):**
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

**Call chain from ExceptionResponseMarshaller.looseUnmarshal (line 113):**
```java
public void looseUnmarshal(OpenWireFormat wireFormat, Object o, DataInput dataIn) throws IOException {
    super.looseUnmarshal(wireFormat, o, dataIn);
    ExceptionResponse info = (ExceptionResponse)o;
    info.setException((java.lang.Throwable) looseUnmarsalThrowable(wireFormat, dataIn));
}
```

**Call from looseUnmarsalThrowable (lines 511-516):**
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);
        String message = looseUnmarshalString(dataIn);
        Throwable o = createThrowable(clazz, message);
        // ... rest of method
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-20**: Improper Input Validation

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability exists in the `createThrowable` method of `BaseDataStreamMarshaller`, which allows arbitrary class instantiation without proper validation.

**Root Cause:**
The `createThrowable` method accepts an externally-controlled `className` parameter from the network and uses it directly with `Class.forName()` and reflection to instantiate any class on the classpath. There is no validation to ensure the class is actually a `Throwable` type before attempting instantiation.

**Attack Vector:**
An attacker can send a specially crafted OpenWire packet with:
1. Data type of 31 (EXCEPTION_RESPONSE)
2. An arbitrary class name (not necessarily a Throwable)
3. A string parameter passed to the constructor

The method will attempt to instantiate ANY class that has a constructor accepting a single String parameter, enabling:
- Remote code execution through gadget chains
- Arbitrary file system operations
- Data exfiltration
- Complete system compromise

**Impact:**
- **CVSS Score**: 9.8/10.0 (Critical)
- **Authentication**: Not required
- **Network Access**: Remote exploitation possible
- **Known Exploitation**: Active exploitation in the wild (CISA KEV catalog)
- Affects all versions before 5.15.16, 5.16.7, 5.17.6, and 5.18.3

## Patch Analysis

The patch adds a validation layer to prevent arbitrary class instantiation:

**1. New validation method in OpenWireUtil.java:**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**2. Modified createThrowable in BaseDataStreamMarshaller.java:**
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW VALIDATION
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    // ...
```

The fix ensures that only classes that extend `Throwable` can be instantiated, preventing the exploitation of arbitrary classes for remote code execution.

## POV Analysis

The POV (pov_0.blob) triggers the vulnerability by sending a malicious OpenWire packet that:
1. Specifies an EXCEPTION_RESPONSE message type
2. Provides a malicious class name (in this case, `jaz.Zer` - a Jazzer security finding class)
3. Successfully instantiates the arbitrary class, triggering Jazzer's security detection

The Jazzer sanitizer caught this as a "FuzzerSecurityIssueHigh: Remote Code Execution" because it detected unrestricted class/object creation based on externally controlled data.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-20]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Protocol Remote Code Execution via Unsafe Deserialization
- **Severity**: Critical (CVSS 9.8)
- **Remediation**: Apply validation to ensure only Throwable classes can be instantiated from untrusted input