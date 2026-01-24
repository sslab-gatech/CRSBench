# Vulnerability Analysis for cpv_4

## Summary
- **CPV ID**: cpv_4
- **Harness**: JenkinsThreeFDP
- **Vulnerability Type**: Insecure Deserialization / Remote Code Execution
- **Origin**: 1-day
- **Release Date**: 08/31/2021
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-21677
  - https://www.jenkins.io/security/advisory/2021-08-31/
  - https://github.com/advisories/GHSA-58pr-hprx-7hg6
  - https://osv.dev/vulnerability/CVE-2021-21677

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: `io/jenkins/plugins/coverage/CoverageProcessor.java:733`
- **Vulnerable Function**: `recoverCoverageResult`
- **DEDUP Token**: ecfed32bee949bf9

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
Unrestricted class/object creation based on externally controlled data may allow
remote code execution depending on available classes on the classpath.
	at jaz.Zer.reportFinding(Zer.java:110)
	at jaz.Zer.reportFindingIfEnabled(Zer.java:105)
	at jaz.Zer.readObject(Zer.java:377)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77)
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.base/java.lang.reflect.Method.invoke(Method.java:568)
	at java.base/java.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:1231)
	at java.base/java.io.ObjectInputStream.readSerialData(ObjectInputStream.java:2434)
	at java.base/java.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:2268)
	at java.base/java.io.ObjectInputStream.readObject0(ObjectInputStream.java:1744)
	at java.base/java.io.ObjectInputStream.readObject(ObjectInputStream.java:514)
	at java.base/java.io.ObjectInputStream.readObject(ObjectInputStream.java:472)
	at io.jenkins.plugins.coverage.CoverageProcessor.recoverCoverageResult(CoverageProcessor.java:733)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.testRecoverCoverage(JenkinsThreeFDP.java:184)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzz(JenkinsThreeFDP.java:112)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzzerTestOneInput(JenkinsThreeFDP.java:79)
DEDUP_TOKEN: ecfed32bee949bf9
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CoverageProcessor.java
- **Function**: recoverCoverageResult
- **Line Range**: 732-733
- **Column Range**: N/A (Java ObjectInputStream.readObject call)

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CompatibleObjectInputStream.java
- **Function**: Constructor and missing resolveClass override (pre-patch)
- **Line Range**: 27-30 (constructor location where protection is needed)
- **Column Range**: N/A

### Code Context

**Crash Site (CoverageProcessor.java:732-733):**
```java
try (ObjectInputStream ois = new CompatibleObjectInputStream(new BufferedInputStream(new FileInputStream(reportFile)))) {
    return (CoverageResult) ois.readObject();  // Line 733 - Insecure deserialization occurs here
}
```

**Root Cause (CompatibleObjectInputStream.java - Pre-Patch):**
The vulnerable code lacks class allowlist validation during deserialization. The class has an `allowList` defined (lines 12-25) but does not override `resolveClass()` to enforce it.

```java
public class CompatibleObjectInputStream extends ObjectInputStream {

    final static List<String> allowList = List.of(
        "io.jenkins.plugins.coverage.targets.CoverageResult",
        "java.util.HashMap",
        "java.util.TreeMap",
        // ... more allowed classes
    );

    public CompatibleObjectInputStream(InputStream in) throws IOException {
        super(in);  // Lines 27-30 - No class validation enforcement
    }
    
    // Missing: resolveClass() override to enforce allowList
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data - The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, allowing attackers to execute arbitrary code.

## Vulnerability Description

This vulnerability (CVE-2021-21677) exists in the Jenkins Code Coverage API Plugin version 1.4.0 and earlier. The plugin fails to apply Jenkins JEP-200 deserialization protections when deserializing Java objects from disk storage.

**Technical Details:**

The vulnerability occurs in the `CoverageProcessor.recoverCoverageResult()` method, which deserializes coverage results from saved report files using `CompatibleObjectInputStream`. While the `CompatibleObjectInputStream` class defines an `allowList` of permitted classes, it does not override the `resolveClass()` method to enforce this allowlist during deserialization.

This allows an attacker who can control the content of serialized report files to instantiate arbitrary classes available on the classpath, leading to Remote Code Execution (RCE). The Jazzer fuzzer detected this by identifying "unrestricted class/object creation based on externally controlled data."

**Attack Vector:**

An attacker with the ability to:
1. Control agent processes (as noted in Jenkins Security Advisory 2021-08-31), or
2. Modify serialized report files in the build directory

can craft malicious serialized Java objects that will be deserialized without validation, triggering arbitrary code execution.

**Impact:**
- Remote Code Execution with the privileges of the Jenkins server
- Complete compromise of the Jenkins instance
- Potential lateral movement to connected systems

## POV Analysis

The POV (Proof of Vulnerability) file `pov_0.blob` (76 bytes) contains a crafted serialized Java object that triggers the deserialization vulnerability when processed by the `recoverCoverageResult()` method. The Jazzer fuzzer detected this as a security issue with:
- **Error Token**: `FuzzerSecurityIssueHigh: Remote Code Execution`
- **Detection Message**: "Unrestricted class/object creation based on externally controlled data"

## Patch Analysis

The patch (`patch_0.diff`) adds the missing `resolveClass()` method override to enforce the allowlist:

**Fix Applied:**
```java
@Override
protected Class<?> resolveClass(ObjectStreamClass desc) throws ClassNotFoundException, IOException {
    if (!allowList.contains(desc.getName())) {
        throw new SecurityException(String.format("Not allows class: %s", desc.getName()));
    }
    return super.resolveClass(desc);
}
```

**How the Fix Works:**
1. Before any class is deserialized, the `resolveClass()` method is called
2. The method checks if the class name exists in the predefined `allowList`
3. If the class is not in the allowlist, a `SecurityException` is thrown, preventing deserialization
4. If the class is allowed, normal deserialization proceeds

This implements the JEP-200 deserialization protection that Jenkins requires for secure object deserialization from disk.

**Root Cause Location:**
The patch clearly identifies the root cause as the missing allowlist enforcement in `CompatibleObjectInputStream.java`. While the crash occurs in `CoverageProcessor.java` when calling `readObject()`, the actual defect is in `CompatibleObjectInputStream.java` where the security control should have been implemented but was missing.

## Recommendations
- **Suggested CWEs**: [CWE-502]
- **Vulnerability Name**: Insecure Deserialization in Jenkins Code Coverage API Plugin
- **CVE Reference**: CVE-2021-21677
- **GHSA Reference**: GHSA-58pr-hprx-7hg6
- **Severity**: High (CVSS 8.8)
- **Origin Classification**: 1-day (confirmed real-world vulnerability with official CVE, GHSA, and Jenkins Security Advisory)