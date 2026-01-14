# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ActivemqOne
- **Vulnerability Type**: Remote Code Execution via Insecure Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: `org.apache.activemq.openwire.v1.BaseDataStreamMarshaller:234`
- **Vulnerable Function**: `createThrowable`
- **DEDUP Token**: `0e98e85958809f6e`

### Stack Trace
The vulnerability is triggered through the following call chain:

```
Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
Unrestricted class/object creation based on externally controlled data may allow
remote code execution depending on available classes on the classpath.
	at jaz.Zer.reportFinding(Zer.java:110)
	at jaz.Zer.reportFindingIfEnabled(Zer.java:105)
	at jaz.Zer.<init>(Zer.java:82)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:77)
	at java.base/jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:480)
	at org.apache.activemq.openwire.v1.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:234)
	at org.apache.activemq.openwire.v1.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:518)
	at org.apache.activemq.openwire.v1.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:114)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: `activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java`
- **Function**: `createThrowable`
- **Line Range**: 230-240
- **Column Range**: Not specified (method level)

### Code Context

**Vulnerable code (lines 230-240):**
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

**The vulnerability exists at line 232:** The code uses `Class.forName()` with an externally controlled `className` parameter without validating that the loaded class is actually a `Throwable`. This allows an attacker to instantiate arbitrary classes on the classpath that have a `String` constructor.

**Call site (line 518 in looseUnmarsalThrowable):**
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);      // Line 516 - attacker-controlled
        String message = looseUnmarshalString(dataIn);    // Line 517 - attacker-controlled
        Throwable o = createThrowable(clazz, message);    // Line 518 - vulnerable call
        ...
```

The attacker controls both the `clazz` (class name) and `message` (constructor parameter) values through the deserialized OpenWire protocol data.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-665**: Improper Initialization

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ with a CVSS score of 10.0. The vulnerability exists in the Java OpenWire protocol marshaller component.

### Root Cause

The `BaseDataStreamMarshaller.createThrowable()` method accepts two externally controlled parameters from deserialized OpenWire protocol messages:
1. `className` - an arbitrary class name
2. `message` - a string passed to the class constructor

The method uses Java reflection to:
1. Load any class on the classpath via `Class.forName(className, ...)`
2. Get a constructor accepting a `String` parameter
3. Instantiate the class with the attacker-controlled message string

**Critically, there is no validation that the loaded class is actually a subclass of `Throwable`.** While the method casts the result to `Throwable`, this happens AFTER the class is already instantiated, meaning the constructor has already executed with the attacker's parameters.

### Attack Vector

An attacker with network access to an ActiveMQ broker or client can:
1. Send a crafted OpenWire protocol message (e.g., `ExceptionResponse`)
2. Specify an arbitrary class name (like `org.springframework.context.support.ClassPathXmlApplicationContext`)
3. Provide a malicious URL as the constructor parameter
4. The vulnerable code instantiates the class, executing arbitrary code

The known exploit uses Spring's `ClassPathXmlApplicationContext` class, which accepts HTTP URLs in its constructor. When instantiated with a remote URL pointing to a malicious XML configuration file, it loads and executes arbitrary code defined in the attacker-controlled XML.

### Impact

- **Remote Code Execution**: Full system compromise
- **No authentication required**: Network access is sufficient
- **Affects brokers and clients**: Both sides of ActiveMQ communication are vulnerable
- **Actively exploited in the wild**: Used by HelloKitty ransomware, Mirai botnet, and cryptocurrency miners

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted OpenWire protocol message:
- Hexdump shows: `07 6a 61 7a 2e 5a 65 72` = "jaz.Zer" (class name)
- Message parameter: "helloworld"

The fuzzer instantiates the class `jaz.Zer`, which is a Jazzer security hook that detects and reports the unsafe deserialization attempt as "Remote Code Execution". This demonstrates the vulnerability without actually executing malicious code.

## Patch Analysis

The patch adds validation to ensure only `Throwable` classes can be instantiated:

**New validation method in `OpenWireUtil.java`:**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**Applied in `BaseDataStreamMarshaller.createThrowable()` at line 232:**
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation added here
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    ...
}
```

This validation occurs **before** the class is instantiated, preventing arbitrary classes from being loaded and executed.

## Recommendations

- **Suggested CWEs**: [CWE-502, CWE-470, CWE-665]
- **Vulnerability Name**: "CVE-2023-46604: Apache ActiveMQ OpenWire Protocol Deserialization RCE"
- **Severity**: Critical (CVSS 10.0)
- **Affected Versions**: ActiveMQ 5.18.0-5.18.2, 5.17.0-5.17.5, 5.16.0-5.16.6, 5.8.0-5.15.15
- **Patched Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3
- **Disclosure Date**: October 27, 2023

---

This vulnerability analysis is ready for use in generating the `vuln.yaml` file for cpv_0.