# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: BeanUtilsOne
- **Vulnerability Type**: Improper Access Control / File Path Traversal (via ClassLoader access)
- **Origin**: 1-day
- **Release Date**: 08/20/2019
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2019-10086
  - https://github.com/advisories/GHSA-wxr5-93ph-8wr9

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: File path traversal
- **Detection Location**: Line 80 of BeanUtilsOne.java (harness file - excluded from vulnerability locations)
- **Vulnerable Function Chain**: `pb.getNestedProperty()` → `PropertyUtilsBean.getNestedProperty()` → access to "class.classLoader" property
- **DEDUP Token**: e800467a23434e73

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: /jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.check(FilePathTraversal.java:346)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkFile(FilePathTraversal.java:304)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkObj(FilePathTraversal.java:288)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.scannerHook(FilePathTraversal.java:267)
	at com.aixcc.beanutils.harnesses.one.BeanUtilsOne.fuzz(BeanUtilsOne.java:80)
	at com.aixcc.beanutils.harnesses.one.BeanUtilsOne.fuzzerTestOneInput(BeanUtilsOne.java:42)
DEDUP_TOKEN: e800467a23434e73
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/main/java/org/apache/commons/beanutils/PropertyUtilsBean.java
- **Function**: resetBeanIntrospectors
- **Line Range**: 188-191
- **Column Range**: 1-6

### Code Context
```java
public final void resetBeanIntrospectors() {
    introspectors.clear();
    introspectors.add(DefaultBeanIntrospector.INSTANCE);
    // MISSING: introspectors.add(SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS);
}
```

**Note**: The crash occurs in the harness file (BeanUtilsOne.java:80) when accessing a File via Scanner after obtaining the ClassLoader through property access. However, per the analysis guidelines, harness files are excluded from vulnerability locations. The root cause is in PropertyUtilsBean.java where the class property suppression is not enabled by default.

## CWE Classification
- **CWE-284**: Improper Access Control
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **CWE-502**: Deserialization of Untrusted Data (as classified by NVD)

## Vulnerability Description

This vulnerability (CVE-2019-10086) affects Apache Commons BeanUtils versions 1.0 through 1.9.3. The core issue is that PropertyUtilsBean does not enable the `SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS` introspector by default, even though this class was added in version 1.9.2 specifically to prevent security issues.

**Technical Details:**

1. **The Problem**: All Java objects have a "class" property that provides access to their Class object. Through this, attackers can access the ClassLoader via property paths like "class.classLoader".

2. **The Attack Vector**: When an application passes externally-controlled property paths to `PropertyUtilsBean.getProperty()` or `getNestedProperty()`, an attacker can craft malicious property paths (e.g., "class.classLoader") to:
   - Access the ClassLoader
   - Load arbitrary classes
   - Instantiate objects with attacker-controlled parameters
   - Achieve arbitrary file access or code execution

3. **The POV**: The proof-of-vulnerability demonstrates this by:
   - Using the property path "class.classLoader" to obtain the ClassLoader
   - Loading `java.io.File` and `java.lang.String` classes
   - Constructing a File object pointing to "/jazzer-traversal"
   - Triggering the Jazzer file path traversal sanitizer

4. **The Fix**: The patch adds `SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS` to the introspectors list in `resetBeanIntrospectors()`. This introspector removes the "class" property from bean introspection, preventing access to the Class object and its associated ClassLoader.

**Impact**: This vulnerability allows remote attackers to manipulate the ClassLoader, potentially leading to:
- Arbitrary file access (as demonstrated by the POV)
- Remote code execution
- Security bypass

## POV Analysis

**POV File Content**: `class.classLoader java.io.File java.lang.String /jazzer-traversal`

The POV demonstrates the vulnerability through a carefully crafted input:

1. **parts[0] = "class.classLoader"**: Property path to access the ClassLoader via PropertyUtilsBean
2. **parts[1] = "java.io.File"**: Class name to load using the obtained ClassLoader
3. **parts[2] = "java.lang.String"**: Parameter type for the File constructor
4. **parts[3] = "/jazzer-traversal"**: Attacker-controlled file path

**Attack Flow**:
```java
ClassLoader a = (ClassLoader) pb.getNestedProperty(pb, "class.classLoader");  // Access ClassLoader
Class c = a.loadClass("java.io.File");                                       // Load File class
Constructor con = c.getConstructor(a.loadClass("java.lang.String"));         // Get constructor
File f = (File) con.newInstance("/jazzer-traversal");                        // Create File with attacker path
Scanner s = new Scanner(f);                                                  // Trigger file access
```

This demonstrates how an attacker can leverage the "class" property exposure to achieve arbitrary file access.

## Patch Analysis

**Patch File**: patch_0.diff

The patch modifies `PropertyUtilsBean.java` at line 188-191:

```diff
 public final void resetBeanIntrospectors() {
     introspectors.clear();
     introspectors.add(DefaultBeanIntrospector.INSTANCE);
+    introspectors.add(SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS);
 }
```

**Fix Explanation**:

The `SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS` is a predefined introspector that removes the "class" property from bean introspection. From the source code:

```java
public static final SuppressPropertiesBeanIntrospector SUPPRESS_CLASS =
        new SuppressPropertiesBeanIntrospector(Collections.singleton("class"));
```

This introspector:
1. Is initialized with the property name "class" to suppress
2. During introspection, removes the "class" property descriptor from the context
3. Prevents PropertyUtilsBean methods from accessing the "class" property

By adding this introspector by default in `resetBeanIntrospectors()`, the fix ensures that:
- The "class" property is not accessible through PropertyUtilsBean methods
- Attackers cannot use property paths like "class.classLoader" to access the ClassLoader
- Applications are protected by default without requiring explicit configuration

## Recommendations

- **Suggested CWEs**: [CWE-284, CWE-470, CWE-502]
- **Vulnerability Name**: Apache Commons BeanUtils ClassLoader Access via Class Property
- **Severity**: HIGH (CVSS 7.3)
- **Fix Version**: Apache Commons BeanUtils 1.9.4+
- **Mitigation**: Upgrade to version 1.9.4 or later, or manually add `SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS` to PropertyUtilsBean instances