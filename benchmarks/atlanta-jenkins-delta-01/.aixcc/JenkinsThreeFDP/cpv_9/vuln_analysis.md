# Vulnerability Analysis for cpv_9

## Summary
- **CPV ID**: cpv_9
- **Harness**: JenkinsThreeFDP
- **Vulnerability Type**: XPath Injection
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (no public CVE found)

## Crash Log Analysis
- **Error Type**: `FuzzerSecurityIssueHigh: XPath Injection`
- **Crash Location**: `jenkins/util/xml/XMLUtils.java:236`
- **Vulnerable Function**: `getValue(String xpath, Document document)`
- **DEDUP Token**: `b6ce41c8b60ffe6b`
- **Injected Query**: `document(2)`

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: XPath Injection
Injected query: document(2)
	at com.code_intelligence.jazzer.sanitizers.XPathInjection.checkXpathExecute(XPathInjection.kt:72)
	at jenkins.util.xml.XMLUtils.getValue(XMLUtils.java:236)
	at io.jenkins.plugins.toyplugin.Api.doXml(Api.java:137)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.testApi(JenkinsThreeFDP.java:265)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzz(JenkinsThreeFDP.java:103)
	at com.aixcc.jenkins.harnesses.three.JenkinsThreeFDP.fuzzerTestOneInput(JenkinsThreeFDP.java:79)
Caused by: javax.xml.xpath.XPathExpressionException: javax.xml.transform.TransformerException: Could not find function: document
	at java.xml/com.sun.org.apache.xpath.internal.jaxp.XPathImpl.compile(XPathImpl.java:170)
	at java.base/java.lang.invoke.MethodHandle.invokeWithArguments(MethodHandle.java:732)
	at com.code_intelligence.jazzer.sanitizers.XPathInjection.checkXpathExecute(XPathInjection.kt:62)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: jenkins/core/src/main/java/jenkins/util/xml/XMLUtils.java
- **Function**: `getValue`
- **Line Range**: 234-237
- **Column Range**: Not specified

### Location 2 (root_cause) - Same as crash_site
- **Type**: root_cause
- **File Path**: jenkins/core/src/main/java/jenkins/util/xml/XMLUtils.java
- **Function**: `getValue`
- **Line Range**: 234-237
- **Column Range**: Not specified

### Code Context

**Vulnerable code (XMLUtils.java lines 234-237):**
```java
public static String getValue(String xpath, Document document) throws XPathExpressionException {
    XPath xPathProcessor = XPathFactory.newInstance().newXPath();
    return xPathProcessor.compile(xpath).evaluate(document);
}
```

The vulnerability exists because:
1. User-controlled XPath expressions are accepted without validation
2. No sanitization of XPath function calls (like `document()`)
3. No secure processing features enabled on the XPathFactory

**Calling code (Api.java lines 127-129):**
```java
// apply exclusions
if (excludes != null) {
    for (String exclude : excludes) {
        XMLUtils.getValue(exclude, dom);  // Line 129 - vulnerable call
    }
}
```

And also at line 137:
```java
list.add(XMLUtils.getValue(xpath, dom));  // Line 137 - vulnerable call
```

## CWE Classification
- **CWE-643**: Improper Neutralization of Data within XPath Expressions ('XPath Injection')
- **CWE-91**: XML Injection (aka Blind XPath Injection)

## Vulnerability Description

This is an **XPath Injection** vulnerability in Jenkins' `XMLUtils.getValue()` method. The method accepts user-controlled XPath expressions and directly compiles and evaluates them against an XML document without any validation or sanitization.

### Attack Vector

An attacker can inject malicious XPath expressions containing function calls (like `document()`, which could be used for XXE attacks or information disclosure). The proof-of-vulnerability demonstrates this by injecting `document(1)` and `document(2)` as XPath expressions.

### Root Cause

The vulnerability stems from:
1. **Lack of input validation**: No checks for dangerous XPath functions or characters
2. **No secure processing**: The XPathFactory is created without enabling secure processing features
3. **Direct compilation**: User input is directly passed to `xPathProcessor.compile()` without sanitization

### Impact

- **Information Disclosure**: Attackers could extract sensitive data from XML documents
- **XML External Entity (XXE) attacks**: Through XPath functions like `document()`
- **Denial of Service**: Malicious XPath expressions could cause resource exhaustion

## POV Analysis

**POV file content**: `exclude document(1) document(2)I`

The POV demonstrates the vulnerability by:
1. Using the `exclude` parameter to inject XPath expressions
2. Injecting `document(1)` and `document(2)` function calls
3. These function calls are detected by Jazzer's XPath injection sanitizer
4. The XPath parser attempts to execute the `document()` function, triggering the security issue

## Patch Analysis

The patch applies defense-in-depth security measures:

### 1. Function Call Detection (Lines 9-11)
```java
if (xpath.indexOf('(') != -1 || xpath.indexOf(')') != -1) {
    throw new XPathExpressionException("XPath functions are not allowed for security reasons");
}
```
- Simple check to reject any XPath expressions containing parentheses
- Prevents all function calls including `document()`, `concat()`, etc.

### 2. Secure Processing Feature (Lines 12-17)
```java
XPathFactory factory = XPathFactory.newInstance();
try {
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
} catch (Exception ignored) {
    // secure-processing not supported
}
```
- Enables secure processing to limit resource consumption
- Provides additional protection against DoS attacks

### 3. Refactored XPath Creation (Line 18)
```java
XPath xPathProcessor = factory.newXPath();
```
- Uses the secured factory instance

## Origin Classification Rationale

**Classified as: synthetic**

**Reasoning:**
1. Conducted comprehensive search for public CVE references:
   - Searched "Jenkins XMLUtils getValue XPath injection vulnerability CVE"
   - Searched "Jenkins XPath injection CVE"
   - Checked Jenkins Security Advisory 2024-05-24
   
2. Found CVE-2024-4184, but it is **NOT a match**:
   - CVE-2024-4184 is about XXE (XML External Entity) in `XpathReader.java` in a **plugin** (hp-application-automation-tools-plugin)
   - Our vulnerability is XPath Injection in `XMLUtils.java` in **Jenkins core**
   - Different vulnerability type, different file, different component
   
3. No exact match found:
   - No CVE found for XPath injection in Jenkins core XMLUtils.getValue() method
   - No security advisories mentioning this specific vulnerability
   - The function signature and fix pattern don't match any known public vulnerability

## Recommendations

### Suggested CWEs
- Primary: **CWE-643** (Improper Neutralization of Data within XPath Expressions)
- Secondary: **CWE-91** (XML Injection/Blind XPath Injection)

### Vulnerability Name
"XPath Injection in Jenkins XMLUtils.getValue()"

### Security Best Practices
1. **Input Validation**: Always validate and sanitize user-controlled XPath expressions
2. **Whitelist Approach**: Only allow safe XPath syntax (element names, attributes, basic operators)
3. **Secure Processing**: Enable secure processing features on XML parsers and XPath processors
4. **Function Restriction**: Disallow dangerous XPath functions like `document()`, `doc()`, etc.
5. **Principle of Least Privilege**: Restrict what XML processing features are available to user input