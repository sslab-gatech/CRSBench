# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: ActivemqOneFDP
- **Vulnerability Type**: Remote Code Execution via Deserialization
- **Origin**: 1-day
- **CVE ID**: CVE-2023-46604
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org.apache.activemq.openwire.v3.BaseDataStreamMarshaller:233
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: 243da7bccc0d787f

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
	at org.apache.activemq.openwire.v3.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:233)
	at org.apache.activemq.openwire.v3.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:517)
	at org.apache.activemq.openwire.v3.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:114)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOneFDP.fuzzerTestOneInput(ActivemqOneFDP.java:40)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v3/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-80

### Location 2 (root_cause) - Same as crash_site
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v3/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-80

### Code Context
The vulnerable code in `BaseDataStreamMarshaller.java` (lines 229-239):

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

**Issue**: The method loads any class by name from the classpath and instantiates it via reflection without validating that the class is actually a Throwable. This allows an attacker to instantiate arbitrary classes that have a String constructor.

The method is called from `looseUnmarsalThrowable` (line 517):
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);
        String message = looseUnmarshalString(dataIn);
        Throwable o = createThrowable(clazz, message);  // <-- Vulnerable call
        ...
```

Which is called from `ExceptionResponseMarshaller.looseUnmarshal` (line 114):
```java
public void looseUnmarshal(OpenWireFormat wireFormat, Object o, DataInput dataIn) throws IOException {
    super.looseUnmarshal(wireFormat, o, dataIn);
    ExceptionResponse info = (ExceptionResponse)o;
    info.setException((java.lang.Throwable) looseUnmarsalThrowable(wireFormat, dataIn));
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-20**: Improper Input Validation

## Vulnerability Description

CVE-2023-46604 is a critical Remote Code Execution vulnerability in Apache ActiveMQ's OpenWire protocol implementation with a CVSS v3.1 score of 10.0. 

The vulnerability exists in the `createThrowable` method of the `BaseDataStreamMarshaller` class. When deserializing OpenWire protocol messages containing exception information, the code accepts an attacker-controlled class name and message string from the network stream. It then uses reflection to:
1. Load any class by name from the classpath using `Class.forName(className, ...)`
2. Find a constructor that takes a String parameter
3. Instantiate the class with the attacker-controlled message string

The critical flaw is that **the code does not validate that the loaded class is actually a Throwable** before attempting to instantiate it. An attacker can specify any class on the classpath that has a String constructor, allowing them to trigger arbitrary code execution through carefully chosen classes.

For example, an attacker could instantiate classes that:
- Execute system commands when constructed
- Load malicious plugins or scripts
- Modify application configuration
- Establish reverse shells

This vulnerability has been actively exploited in the wild to deploy Kinsing malware, cryptocurrency miners, HelloKitty ransomware, and other malicious payloads on vulnerable ActiveMQ installations.

## POV Analysis
The POV file (39 bytes) contains a serialized OpenWire message crafted to exploit this vulnerability. The crash log shows that when the fuzzing harness unmarshals this data, it attempts to instantiate the `jaz.Zer` class (a Jazzer security hook class) which triggers the remote code execution detection, demonstrating the vulnerability.

## Patch Analysis

The patch adds validation to prevent arbitrary class instantiation:

**File 1**: `activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireUtil.java`
- **Change**: Adds a new `validateIsThrowable` method that checks if a class is assignable to Throwable
- **Purpose**: Provides centralized validation logic

```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**File 2**: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v3/BaseDataStreamMarshaller.java`
- **Change**: Adds validation call after loading the class but before instantiation (line 232)
- **Purpose**: Ensures only legitimate Throwable classes can be instantiated

```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- Added validation
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    ...
```

The fix ensures that only classes extending Throwable can be instantiated, blocking the remote code execution attack vector while maintaining legitimate exception handling functionality.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-20]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Protocol Remote Code Execution via Unsafe Deserialization
- **CVSS Score**: 10.0 (Critical)
- **Affected Versions**: ActiveMQ < 5.15.16, 5.16.0-5.16.6, 5.17.0-5.17.5, 5.18.0-5.18.2
- **Patched Versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3