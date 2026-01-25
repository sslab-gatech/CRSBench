# Vulnerability Analysis for cpv_3

## Summary
- **CPV ID**: cpv_3
- **Harness**: ActivemqOneFDP
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: BaseDataStreamMarshaller.java:233 (createThrowable method)
- **Vulnerable Function**: `createThrowable`
- **DEDUP Token**: ca0174ea7e1f39a6

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
	at com.aixcc.activemq.harnesses.one.ActivemqOneFDP.fuzzerTestOneInput(ActivemqOneFDP.java:40)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v4/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 229-239
- **Column Range**: 1-999

### Code Context (Vulnerable - Before Patch)
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        // NO VALIDATION - can instantiate ANY class, not just Throwable!
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

### Location 2 (crash_site - where instantiation happens)
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v4/BaseDataStreamMarshaller.java
- **Function**: looseUnmarsalThrowable
- **Line Range**: 512-545
- **Column Range**: 1-999

### Code Context (Call Chain)
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);          // Attacker-controlled class name
        String message = looseUnmarshalString(dataIn);        // Attacker-controlled message
        Throwable o = createThrowable(clazz, message);        // Vulnerable call - no validation
        // ... rest of method
    }
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - secondary impact

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller with a CVSS score of 10.0.

### Root Cause
The `createThrowable` method in `BaseDataStreamMarshaller` accepts an externally-controlled class name and message from the OpenWire protocol and uses reflection to instantiate any class available on the classpath that has a String constructor. The vulnerability exists because:

1. **No type validation**: The method does NOT verify that the class being instantiated actually extends `Throwable`
2. **Unsafe reflection**: Uses `Class.forName()` with attacker-controlled input
3. **Arbitrary instantiation**: Can instantiate ANY class with a String constructor, not just Exception classes

### Attack Vector
An attacker with network access to an ActiveMQ OpenWire broker (default port 61616) or client can:
1. Send a malicious OpenWire packet containing an `ExceptionResponse` object
2. Specify an arbitrary class name (e.g., `ClassPathXmlApplicationContext`, or in this POV case, `jaz.Zer`)
3. Trigger instantiation of that class with attacker-controlled constructor arguments
4. Achieve remote code execution by instantiating classes that perform dangerous operations in their constructors

### Impact
- **Remote Code Execution**: Attackers can execute arbitrary code on the server
- **Full system compromise**: Critical severity (CVSS 10.0)
- **Active exploitation**: Listed in CISA's Known Exploited Vulnerabilities Catalog
- **Real-world attacks**: Used to deploy HelloKitty ransomware and Kinsing cryptominers

## POV Analysis

The POV file (`pov_0.blob`) contains a serialized OpenWire message with:
- Class name: `jaz.Zer` (a Jazzer fuzzer security checker class, NOT a Throwable)
- Message: `helloworld`

When ActiveMQ processes this POV through the OpenWire unmarshalling pipeline:
1. `ExceptionResponseMarshaller.looseUnmarshal()` is called (line 113)
2. Calls `looseUnmarsalThrowable()` which reads the class name "jaz.Zer" from the POV
3. Calls `createThrowable("jaz.Zer", "helloworld")` 
4. Uses reflection to instantiate `jaz.Zer` with the message parameter
5. The `jaz.Zer` constructor detects the security issue and throws `FuzzerSecurityIssueHigh`

This demonstrates the vulnerability: an attacker can instantiate ANY class with a String constructor, not just legitimate Throwable classes.

## Patch Analysis

The patch (patch_0.diff) fixes the vulnerability by adding validation:

### New Validation Method (OpenWireUtil.java)
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

### Modified createThrowable Method
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

The fix ensures that only classes that actually extend `Throwable` can be instantiated, preventing arbitrary class instantiation and remote code execution.

### Affected Versions
- Apache ActiveMQ versions before 5.15.16, 5.16.0-5.16.6, 5.17.0-5.17.5, and 5.18.0-5.18.2

### Patched Versions
- 5.15.16, 5.16.7, 5.17.6, 5.18.3 and later

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-78]
- **Vulnerability Name**: Apache ActiveMQ OpenWire Remote Code Execution via Unsafe Deserialization
- **Severity**: Critical (CVSS 10.0)
- **Mitigation**: Upgrade to patched versions immediately, or disable OpenWire protocol if not needed