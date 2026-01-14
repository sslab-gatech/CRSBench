# Vulnerability Analysis for cpv_7

## Summary
- **CPV ID**: cpv_7
- **Harness**: ActivemqOneFDP
- **Vulnerability Type**: Remote Code Execution via Insecure Deserialization
- **Origin**: 1-day
- **Release Date**: 10/27/2023
- **CVE ID**: CVE-2023-46604
- **GHSA ID**: GHSA-crg9-44h2-xw35
- **References**:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://github.com/advisories/GHSA-crg9-44h2-xw35
  - https://osv.dev/vulnerability/CVE-2023-46604
  - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt

## Crash Log Analysis

### Error Type
`FuzzerSecurityIssueHigh: Remote Code Execution` - This is a Jazzer security issue detection indicating unrestricted class/object creation based on externally controlled data, which may allow remote code execution depending on available classes on the classpath.

### Crash Location
- **File**: `org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
- **Function**: `createThrowable`
- **Line**: 232

### DEDUP Token
`0187a068436cb811`

### Stack Trace
```java
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
	at com.aixcc.activemq.harnesses.one.ActivemqOneFDP.fuzzerTestOneInput(ActivemqOneFDP.java:40)
```

The stack trace shows the vulnerability is triggered during OpenWire protocol deserialization when unmarshalling exception responses.

## Vulnerable Code Location(s)

### Location 1: root_cause
- **Type**: root_cause
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java
- **Function**: createThrowable
- **Line Range**: 228-238
- **Column Range**: 1-6 (method declaration)

This is the root cause location where arbitrary class instantiation occurs without validation.

### Location 2: crash_site
- **Type**: crash_site
- **File Path**: activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java
- **Function**: looseUnmarsalThrowable
- **Line Range**: 516-516
- **Column Range**: 25-54

This is where the vulnerable `createThrowable` method is called during deserialization.

### Vulnerable Code Context

**Root Cause (lines 228-238):**
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

**Crash Site (lines 511-516):**
```java
protected Throwable looseUnmarsalThrowable(OpenWireFormat wireFormat, DataInput dataIn)
    throws IOException {
    if (dataIn.readBoolean()) {
        String clazz = looseUnmarshalString(dataIn);
        String message = looseUnmarshalString(dataIn);
        Throwable o = createThrowable(clazz, message);  // Vulnerable call
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This is **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol marshaller with a CVSS score of **9.8/10.0 (Critical)**.

### Technical Details

The vulnerability exists in the `createThrowable` method of `BaseDataStreamMarshaller` class. The method accepts an arbitrary class name from untrusted network input and uses reflection to instantiate that class without any validation that the class is actually a `Throwable` subclass.

**Attack Vector:**
1. An attacker sends a malicious OpenWire protocol message to an ActiveMQ broker or client
2. During deserialization of an `ExceptionResponse`, the `looseUnmarsalThrowable` method reads a class name from the input stream
3. The class name is passed directly to `createThrowable`, which uses `Class.forName()` to load any class on the classpath
4. The class is instantiated via reflection with an attacker-controlled string parameter
5. The attacker can instantiate dangerous classes like `org.springframework.context.support.ClassPathXmlApplicationContext` (available in ActiveMQ's classpath) with a URL pointing to a malicious XML configuration file
6. This leads to arbitrary code execution on the target system

**Impact:**
- Remote Code Execution (RCE) with full system privileges
- Complete system compromise
- Data exfiltration, malware installation, lateral movement
- Affects both ActiveMQ brokers and clients

**Affected Versions:**
- Apache ActiveMQ versions before 5.15.16
- Apache ActiveMQ 5.16.0 through 5.16.6
- Apache ActiveMQ 5.17.0 through 5.17.5
- Apache ActiveMQ 5.18.0 through 5.18.2
- Apache ActiveMQ Legacy OpenWire Module (all versions affected)

This vulnerability was actively exploited in the wild and added to CISA's Known Exploited Vulnerabilities (KEV) catalog.

## POV Analysis

The POV file (`pov_0.blob`) contains a malicious OpenWire protocol message crafted to trigger the vulnerability. The POV successfully demonstrates the security issue by:

1. Crafting an OpenWire message containing an ExceptionResponse
2. Embedding a malicious class name (likely a gadget class like `jaz.Zer` used by Jazzer fuzzer for testing)
3. Triggering the instantiation during deserialization
4. Jazzer's security hooks detect the dangerous reflection-based instantiation and report it as a `FuzzerSecurityIssueHigh: Remote Code Execution`

The reproducer was written to `Crash_1a7e10e0437adc2896476774ffd5d706d8f80392.java` for further analysis.

## Patch Analysis

The patch adds validation to prevent arbitrary class instantiation:

**File 1: `activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireUtil.java`**
- Adds a new `validateIsThrowable(Class<?> clazz)` method
- This method checks if the loaded class is actually assignable to `Throwable`
- Throws `IllegalArgumentException` if the class is not a valid Throwable subclass

**File 2: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`**
- Adds a call to `OpenWireUtil.validateIsThrowable(clazz)` immediately after `Class.forName()`
- This validation ensures only legitimate Throwable classes can be instantiated
- Prevents gadget classes (like Spring's ClassPathXmlApplicationContext) from being loaded

**Key Fix:**
```java
Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
OpenWireUtil.validateIsThrowable(clazz);  // <-- NEW: Validation added
Constructor constructor = clazz.getConstructor(new Class[] {String.class});
```

The fix is applied to multiple versions of the marshaller (v1-v12) across both the legacy OpenWire module and the main client.

## Recommendations

### For vuln.yaml Generation:
- **CWE IDs**: [502, 470, 94]
- **Vulnerability Type**: remote-code-execution
- **Vulnerability Name**: "OpenWire Protocol Insecure Deserialization RCE"
- **Severity**: Critical
- **CVSS Score**: 9.8-10.0

### Locations to Include:
1. **root_cause**: 
   - File: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
   - Function: `createThrowable`
   - Lines: 228-238

2. **crash_site**:
   - File: `activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v8/BaseDataStreamMarshaller.java`
   - Function: `looseUnmarsalThrowable`
   - Line: 516

### Additional Context:
- This vulnerability affects multiple protocol versions (v1-v12)
- The same pattern exists in other marshallers: `ExceptionResponseMarshaller`, `ConnectionErrorMarshaller`, `MessageAckMarshaller`
- The patch must be applied to all versions to fully remediate the vulnerability

---

**Analysis completed. This is a well-documented, critical 1-day vulnerability with confirmed CVE, GHSA, and OSV entries, active exploitation history, and clear patch information.**