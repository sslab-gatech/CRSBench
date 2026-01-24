# Vulnerability Analysis for cpv_11

## Summary
- **CPV ID**: cpv_11
- **Harness**: ActivemqOneFDP
- **Vulnerability Type**: Remote Code Execution via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: BaseDataStreamMarshaller.java:234 (in `createThrowable` method)
- **Vulnerable Function**: `createThrowable`
- **DEDUP Token**: b13a314ce9d138a8

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
	at org.apache.activemq.openwire.v12.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:234)
	at org.apache.activemq.openwire.v12.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:518)
	at org.apache.activemq.openwire.v12.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
	at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
	at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
	at com.aixcc.activemq.harnesses.one.ActivemqOneFDP.fuzzerTestOneInput(ActivemqOneFDP.java:40)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v12/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 234-234
- **Column Range**: 1-80

### Location 2 (root_cause) - Same as crash_site
- **Type**: root_cause
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v12/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 230-240
- **Column Range**: 1-80

### Code Context
**Vulnerable code (before patch):**
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

The vulnerability occurs because the method accepts an arbitrary `className` from externally-controlled data and instantiates it without validating that the class actually extends `Throwable`. An attacker can provide any class name that has a String constructor, allowing arbitrary object instantiation and remote code execution.

**Call site in looseUnmarshalThrowable:**
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);        // Attacker-controlled
        String message = looseUnmarshalString(dataIn);      // Attacker-controlled
        Throwable o = createThrowable(clazz, message);      // Vulnerable call
        ...
    }
}
```

**Used in ExceptionResponseMarshaller:**
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
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is CVE-2023-46604, a critical remote code execution vulnerability in Apache ActiveMQ with a CVSS score of 10.0/10.0. The vulnerability allows a remote attacker with network access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol.

The root cause is in the `BaseDataStreamMarshaller.createThrowable()` method, which accepts an arbitrary class name from externally-controlled data (via OpenWire protocol deserialization) and instantiates it without proper validation. The method uses reflection to:
1. Load any class by name using `Class.forName()`
2. Find a constructor that accepts a String parameter
3. Instantiate the class with an attacker-controlled message

While the method is intended to deserialize legitimate exception/throwable objects, it fails to validate that the loaded class actually extends `Throwable` before instantiation. This allows an attacker to:
- Send a specially crafted OpenWire packet containing an `ExceptionResponse`
- Provide an arbitrary class name (not necessarily a Throwable)
- Trigger instantiation of any class on the classpath that has a String constructor
- Achieve remote code execution by instantiating malicious classes

The Jazzer fuzzer's deserialization hook detected this vulnerability by identifying unrestricted class/object creation based on externally controlled data.

**Attack vector:**
1. Attacker connects to ActiveMQ's OpenWire TCP port (default: 61616)
2. Sends a crafted OpenWire packet with an `ExceptionResponse` object
3. Provides arbitrary class name (e.g., a class that executes commands in its constructor)
4. ActiveMQ deserializes the message and calls `createThrowable()`
5. The arbitrary class is instantiated, leading to code execution

## POV Analysis
The POV (pov_0.blob) is a crafted OpenWire protocol message that triggers the vulnerability by providing a malicious class name (`jaz.Zer`) that is not a legitimate Throwable but has a String constructor. When ActiveMQ attempts to deserialize this ExceptionResponse, it instantiates the malicious class, which is detected by Jazzer's security hooks as a Remote Code Execution attempt.

## Patch Analysis

The patch introduces a validation function to prevent arbitrary class instantiation:

**Added to OpenWireUtil.java:**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**Applied in BaseDataStreamMarshaller.createThrowable():**
```java
private Throwable createThrowable(String className, String message) {
    try {
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // NEW: Validation check
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The fix ensures that only classes that actually extend `Throwable` can be instantiated through this deserialization path, preventing the remote code execution vulnerability. The validation happens after `Class.forName()` but before the constructor is invoked, rejecting any class that is not a subclass of `Throwable`.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-94]
- **Vulnerability name**: Apache ActiveMQ OpenWire Deserialization Remote Code Execution (CVE-2023-46604)
- **Severity**: Critical (CVSS 10.0)
- **Affected versions**: Apache ActiveMQ < 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3
- **Fixed versions**: 5.15.16, 5.16.7, 5.17.6, 5.18.3