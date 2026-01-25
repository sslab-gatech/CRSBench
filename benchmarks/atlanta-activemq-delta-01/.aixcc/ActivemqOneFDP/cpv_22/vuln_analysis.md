# Vulnerability Analysis for cpv_10

## Summary
- **CPV ID**: cpv_10
- **Harness**: ActivemqOneFDP
- **Vulnerability Type**: Unsafe Deserialization / Remote Code Execution
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org.apache.activemq.openwire.v11.BaseDataStreamMarshaller:232
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: 42ee430b4d82aeb5

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
	at com.aixcc.activemq.harnesses.one.ActivemqOneFDP.fuzzerTestOneInput(ActivemqOneFDP.java:40)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-5

### Code Context (Before Patch)
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

The vulnerability exists in line 230-232 where:
1. Line 230: `Class.forName()` loads any class specified by the attacker-controlled `className` parameter
2. Line 231: Gets the constructor without validating the class type
3. Line 232: Instantiates the arbitrary class without checking if it's actually a Throwable

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.java
- **Function**: looseUnmarsalThrowable
- **Line Range**: 511-516
- **Column Range**: 1-5

### Code Context (Crash Site)
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);  // Line 514: Attacker-controlled class name
        String message = looseUnmarshalString(dataIn); // Line 515: Attacker-controlled message
        Throwable o = createThrowable(clazz, message); // Line 516: Calls vulnerable function
        // ...
```

This is where the attacker-controlled `clazz` string is read from the OpenWire protocol message and passed to `createThrowable()`.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

**CVE-2023-46604** is a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol implementation, affecting versions prior to 5.15.16, 5.16.7, 5.17.6, and 5.18.3. The vulnerability has a CVSS score of 10.0 (Critical).

### Root Cause
The vulnerability exists in the `createThrowable()` method within `BaseDataStreamMarshaller.java`. This method is designed to deserialize exception objects from OpenWire protocol messages. However, it fails to validate that the class name provided in the serialized data actually extends `Throwable` before instantiating it.

The attack flow is:
1. Attacker sends a crafted OpenWire protocol message with an `ExceptionResponse` command
2. The `ExceptionResponseMarshaller.looseUnmarshal()` method processes this message
3. It calls `looseUnmarsalThrowable()` which extracts the attacker-controlled class name
4. This class name is passed to `createThrowable()` which uses reflection to instantiate ANY class on the classpath
5. The attacker can specify dangerous classes like `ClassPathXmlApplicationContext` from Spring Framework (included in ActiveMQ)
6. When instantiated with a malicious XML configuration URL, this leads to arbitrary code execution

### Impact
- **Remote Code Execution**: No authentication required
- **Network-accessible**: Can be exploited remotely
- **Critical severity**: CVSS 10.0 score
- **Active exploitation**: Used by HelloKitty ransomware and Kinsing malware in the wild since October 2023
- **CISA KEV**: Listed in CISA's Known Exploited Vulnerabilities Catalog

## POV Analysis

The POV file (39 bytes) contains a crafted OpenWire protocol message that triggers the vulnerability:

```
00000000  00 00 00 22 1f 00 00 00  00 00 00 00 00 00 01 01  |..."............|
00000010  00 07 6a 61 7a 2e 5a 65  72 01 00 0a 68 65 6c 6c  |..jaz.Zer...hell|
00000020  6f 77 6f 72 6c 64 0b                              |oworld.|
```

Key observations:
- Byte 0x1f: Indicates an ExceptionResponse command type
- String "jaz.Zer": The attacker-specified class name (a Jazzer hook class that detects the vulnerability)
- String "helloworld": The message parameter for the constructor

The POV demonstrates that an attacker can instantiate the `jaz.Zer` class (which is designed to detect code injection vulnerabilities). In real attacks, this would be replaced with `org.springframework.context.support.ClassPathXmlApplicationContext` to achieve remote code execution.

## Patch Analysis

The patch adds validation to ensure only legitimate Throwable classes can be instantiated:

### Changes to OpenWireUtil.java
```java
/**
 * Verify that the provided class extends {@link Throwable} and throw an
 * {@link IllegalArgumentException} if it does not.
 */
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

### Changes to BaseDataStreamMarshaller.java
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW: Validation added here
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The fix ensures that after loading the class with `Class.forName()`, the code validates that it's actually assignable to `Throwable` before proceeding with instantiation. This prevents attackers from instantiating arbitrary classes like `ClassPathXmlApplicationContext`.

## Recommendations

### Suggested CWEs
- CWE-502 (Primary)
- CWE-470 (Secondary)
- CWE-94 (Tertiary)

### Vulnerability Name
"Apache ActiveMQ OpenWire Protocol Unsafe Deserialization (CVE-2023-46604)"

### Severity
Critical - CVSS 10.0

### Remediation Priority
Immediate - This vulnerability is actively exploited in the wild and listed in CISA's Known Exploited Vulnerabilities Catalog.