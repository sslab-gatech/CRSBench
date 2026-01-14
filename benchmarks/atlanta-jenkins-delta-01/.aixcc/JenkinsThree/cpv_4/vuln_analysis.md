# Vulnerability Analysis for cpv_4

## Summary
- **CPV ID**: cpv_4
- **Harness**: JenkinsThree
- **Vulnerability Type**: Insecure Deserialization / Remote Code Execution
- **Origin**: 1-day
- **Release Date**: 08/31/2021
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-21677
  - https://www.jenkins.io/security/advisory/2021-08-31/

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueHigh: Remote Code Execution
- **Error Message**: "Unrestricted class/object creation based on externally controlled data may allow remote code execution depending on available classes on the classpath."
- **Crash Location**: `io.jenkins.plugins.coverage.CoverageProcessor.recoverCoverageResult()` at line 733
- **Detection Point**: `jaz.Zer.readObject()` - Jazzer's deserialization hook detected the unsafe deserialization
- **DEDUP Token**: b0414edf4dd428ff

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
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.testRecoverCoverage(JenkinsThree.java:184)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzz(JenkinsThree.java:112)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzzerTestOneInput(JenkinsThree.java:79)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CoverageProcessor.java
- **Function**: recoverCoverageResult
- **Line Range**: 733-733
- **Column Range**: 1-50

**Code Context (CoverageProcessor.java:729-735)**:
```java
public static CoverageResult recoverCoverageResult(final Run<?, ?> run) throws IOException, ClassNotFoundException {
    File reportFile = new File(run.getRootDir(), DEFAULT_REPORT_SAVE_NAME);

    try (ObjectInputStream ois = new CompatibleObjectInputStream(new BufferedInputStream(new FileInputStream(reportFile)))) {
        return (CoverageResult) ois.readObject();  // Line 733 - Crash site
    }
}
```

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CompatibleObjectInputStream.java
- **Function**: CompatibleObjectInputStream (class implementation - missing resolveClass override)
- **Line Range**: 10-52
- **Column Range**: 1-1

**Code Context (CompatibleObjectInputStream.java:10-52)**:
```java
public class CompatibleObjectInputStream extends ObjectInputStream {

    final static List<String> allowList = List.of(
        "io.jenkins.plugins.coverage.targets.CoverageResult",
        "java.util.HashMap",
        "java.util.TreeMap",
        // ... more allowed classes
    );

    public CompatibleObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    // MISSING: resolveClass() override to validate against allowList
    
    @Override
    protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
        // Only handles serialVersionUID compatibility, NOT security validation
        // ...
    }
}
```

**Root Cause Explanation**: The `CompatibleObjectInputStream` class defines an `allowList` of safe classes but never validates deserialized objects against it. The class only overrides `readClassDescriptor()` to handle serialVersionUID mismatches, but does not override `resolveClass()` to enforce the allowlist. This allows arbitrary classes on the classpath to be deserialized, leading to remote code execution.

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

## Vulnerability Description

This is **CVE-2021-21677**, an insecure deserialization vulnerability in Jenkins Code Coverage API Plugin version 1.4.0 and earlier.

**Vulnerability Details**:
The Code Coverage API plugin fails to apply Jenkins JEP-200 deserialization protection when deserializing Java objects from disk. The `CompatibleObjectInputStream` class extends `ObjectInputStream` and defines an allowlist of safe classes, but crucially **fails to enforce this allowlist during deserialization**.

**Attack Vector**:
1. The `CoverageProcessor.recoverCoverageResult()` method deserializes coverage data from a file on disk using `CompatibleObjectInputStream`
2. An attacker who can control the contents of the serialized coverage file can inject malicious serialized objects
3. Since `CompatibleObjectInputStream` doesn't validate classes against the allowlist during deserialization, any class on the classpath can be instantiated
4. Using gadget chains available on the classpath, an attacker can achieve remote code execution

**Impact**: 
- Remote Code Execution (RCE)
- Compromise of Jenkins server
- Potential lateral movement to connected systems

**Detection**:
Jazzer's deserialization sanitizer (part of the fuzzing framework) detected this vulnerability by monitoring `ObjectInputStream.readObject()` calls and identifying when arbitrary classes are being deserialized without proper validation.

## POV Analysis

A POV file exists at `benchmarks/atlanta-jenkins-delta-01/.aixcc/JenkinsThree/cpv_4/blobs/pov_0.blob` (76 bytes). This is a crafted serialized Java object that triggers the vulnerability when deserialized by `CoverageProcessor.recoverCoverageResult()`. The POV demonstrates that an attacker-controlled serialized object can bypass the intended class restrictions and trigger the security issue.

## Patch Analysis

The patch adds the missing `resolveClass()` method to `CompatibleObjectInputStream`:

**Patch Location**: `plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CompatibleObjectInputStream.java`

**What Changed**:
```java
@Override
protected Class<?> resolveClass(ObjectStreamClass desc) throws ClassNotFoundException, IOException {
    if (!allowList.contains(desc.getName())) {
        throw new SecurityException(String.format("Not allows class: %s", desc.getName()));
    }
    return super.resolveClass(desc);
}
```

**Fix Explanation**:
- Overrides `resolveClass()` which is called before each class is deserialized
- Validates the class name against the predefined `allowList`
- Throws a `SecurityException` if an unauthorized class is encountered
- This implements the JEP-200 deserialization protection that was previously missing

**Why This Fixes the Vulnerability**:
By validating all classes during deserialization against the allowlist, the fix prevents arbitrary classes from being instantiated. This blocks exploitation via gadget chains, as attackers can no longer deserialize classes they control.

## Recommendations

### Vulnerability Metadata for vuln.yaml:
- **Suggested CWEs**: [CWE-502, CWE-470]
- **Vulnerability Name**: "Insecure Deserialization in Code Coverage API Plugin"
- **Severity**: High (allows Remote Code Execution)
- **Origin**: 1-day (CVE-2021-21677)
- **Release Date**: 08/31/2021

### Location Information:
1. **crash_site**: 
   - File: `plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CoverageProcessor.java`
   - Function: `recoverCoverageResult`
   - Lines: 733

2. **root_cause**:
   - File: `plugins/code-coverage-api-plugin/src/main/java/io/jenkins/plugins/coverage/CompatibleObjectInputStream.java`
   - Class: `CompatibleObjectInputStream`
   - Lines: 10-52 (entire class - missing security validation in resolveClass)