# Vulnerability Analysis for cpv_10

## Summary
- **CPV ID**: cpv_10
- **Harness**: ActivemqVariantOne
- **Vulnerability Type**: Remote Code Execution via Arbitrary Class Instantiation
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://activemq.apache.org/news/cve-2023-46604

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: org.apache.activemq.openwire.v11.BaseDataStreamMarshaller.createThrowable:232
- **Vulnerable Function**: createThrowable
- **DEDUP Token**: f695adcbca5fdb20

### Stack Trace
The vulnerability is triggered through the following call chain:
```
at org.apache.activemq.openwire.v11.BaseDataStreamMarshaller.createThrowable(BaseDataStreamMarshaller.java:232)
at org.apache.activemq.openwire.v11.BaseDataStreamMarshaller.looseUnmarsalThrowable(BaseDataStreamMarshaller.java:516)
at org.apache.activemq.openwire.v11.ExceptionResponseMarshaller.looseUnmarshal(ExceptionResponseMarshaller.java:113)
at org.apache.activemq.openwire.OpenWireFormat.doUnmarshal(OpenWireFormat.java:379)
at org.apache.activemq.openwire.OpenWireFormat.unmarshal(OpenWireFormat.java:290)
at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
```

The Jazzer sanitizer detected this as: "Unrestricted class/object creation based on externally controlled data may allow remote code execution depending on available classes on the classpath."

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-239
- **Column Range**: 1-6

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: activemq-client/src/main/java/org/apache/activemq/openwire/v11/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 231-233
- **Column Range**: 1-60

### Code Context

**Vulnerable Code (Before Patch):**
```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
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

**Key Issue:** Line 231 loads an arbitrary class based on externally-controlled input (`className`) without validating that the class is actually a Throwable subclass. Line 232-233 then instantiate this arbitrary class via reflection.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller. The vulnerability exists in the `createThrowable` method of the `BaseDataStreamMarshaller` class, which is used to deserialize exception objects from the OpenWire protocol.

**Root Cause:**
The `createThrowable` method accepts a className string from untrusted network input and uses reflection to instantiate it without validating that the class extends `Throwable`. This allows an attacker to instantiate any arbitrary class on the classpath that has a constructor accepting a single String parameter.

**Attack Vector:**
1. An attacker sends a malicious OpenWire `ExceptionResponse` command to the broker or client
2. The `looseUnmarshal` method in `ExceptionResponseMarshaller` calls `looseUnmarsalThrowable`
3. `looseUnmarsalThrowable` reads the attacker-controlled className from the data stream
4. `createThrowable` uses `Class.forName()` to load the arbitrary class
5. The arbitrary class is instantiated via reflection with an attacker-controlled String parameter
6. Known exploits use `ClassPathXmlApplicationContext` to load malicious XML configuration files from remote servers, leading to remote code execution

**Impact:**
- CVSS Score: 10.0 (Critical)
- Full remote code execution on vulnerable ActiveMQ brokers and clients
- Attackers can execute arbitrary shell commands
- Active exploitation observed in the wild, including HelloKitty ransomware deployments

## POV Analysis

The POV file (39 bytes) contains a crafted OpenWire message with the malicious class name `jaz.Zer` (a Jazzer-specific test class used to trigger the security finding). The payload structure shows:
- Command type byte (0x0b)
- Length fields
- Class name: `jaz.Zer` (7 bytes)
- Message: `helloworld` (10 bytes)

This POV demonstrates that an attacker can control both the className and message parameters passed to the vulnerable constructor instantiation.

## Patch Analysis

The patch adds a validation layer to prevent arbitrary class instantiation:

**File 1: OpenWireUtil.java (NEW METHOD)**
```java
public static void validateIsThrowable(Class<?> clazz) {
    if (!Throwable.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Class " + clazz + " is not assignable to Throwable");
    }
}
```

**File 2: BaseDataStreamMarshaller.java (ADDED VALIDATION)**
```java
private Throwable createThrowable(String className, String message) {
    try {
        if (!className.startsWith("j")) {return new Throwable(className + ": " + message);}
        Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
        OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW VALIDATION
        Constructor constructor = clazz.getConstructor(new Class[] {String.class});
        return (Throwable)constructor.newInstance(new Object[] {message});
    } catch (IllegalArgumentException e) {
        return e;
    } catch (Throwable e) {
        return new Throwable(className + ": " + message);
    }
}
```

The fix ensures that only classes that extend `Throwable` can be instantiated, preventing arbitrary code execution through gadget classes like `ClassPathXmlApplicationContext`.

## Recommendations
- **Suggested CWEs**: [CWE-502, CWE-470, CWE-94]
- **Vulnerability Name**: OpenWire Protocol Arbitrary Class Instantiation RCE
- **Severity**: Critical (CVSS 10.0)
- **Remediation**: Upgrade to Apache ActiveMQ versions 5.15.16, 5.16.7, 5.17.6, or 5.18.3 or later