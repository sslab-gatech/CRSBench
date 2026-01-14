# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: Rdf4jOne
- **Vulnerability Type**: XML External Entity (XXE) Injection / Server-Side Request Forgery (SSRF)
- **Origin**: 1-day
- **Release Date**: 08/20/2018
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1000644
  - https://github.com/eclipse-rdf4j/rdf4j/issues/1056
  - https://github.com/eclipse/rdf4j/pull/1146
  - https://0dd.zone/2018/08/05/rdf4j-XXE/

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **Attack Vector**: XML External Entity (XXE) injection leading to SSRF
- **Attempted Connection**: jazzer.example.com:80
- **DEDUP Token**: 376ed7d96d42f0c2

### Stack Trace
The vulnerability is triggered when parsing an RDF/XML document containing external entity references:

```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
Attempted connection to: jazzer.example.com:80
...
at java.base/sun.net.www.protocol.http.HttpURLConnection.connect(HttpURLConnection.java:1057)
at java.base/sun.net.www.protocol.http.HttpURLConnection.getInputStream0(HttpURLConnection.java:1665)
at java.xml/com.sun.org.apache.xerces.internal.impl.XMLEntityManager.setupCurrentEntity(XMLEntityManager.java:677)
at java.xml/com.sun.org.apache.xerces.internal.impl.XMLDocumentFragmentScannerImpl.scanEntityReference(XMLDocumentFragmentScannerImpl.java:1859)
...
at org.eclipse.rdf4j.rio.rdfxml.RDFXMLParser.parse(RDFXMLParser.java:328)
at org.eclipse.rdf4j.rio.rdfxml.RDFXMLParser.parse(RDFXMLParser.java:205)
at com.aixcc.rdf4j.harnesses.one.Rdf4jOne.fuzz(Rdf4jOne.java:47)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: rio/api/src/main/java/org/eclipse/rdf4j/rio/helpers/XMLParserSettings.java
- **Description**: Missing XXE protection settings in XML parser configuration
- **Line Range**: 35-46 (vulnerable code section)
- **Vulnerability**: The vulnerable code only had `SECURE_PROCESSING` and `LOAD_EXTERNAL_DTD` (set to true) settings, allowing external entities to be processed

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: rio/rdfxml/src/main/java/org/eclipse/rdf4j/rio/rdfxml/RDFXMLParser.java
- **Function**: parse
- **Line Range**: 242-295 (parse method with XML reader configuration)
- **Description**: The XML parsing method that processes the malicious input without proper XXE protections

### Code Context

**Vulnerable XMLParserSettings.java (before patch):**
```java
public static final RioSetting<Boolean> LOAD_EXTERNAL_DTD = new RioSettingImpl<Boolean>(
    "http://apache.org/xml/features/nonvalidating/load-external-dtd", "Load External DTD", true);
// Missing: DISALLOW_DOCTYPE_DECL
// Missing: EXTERNAL_GENERAL_ENTITIES
// Missing: EXTERNAL_PARAMETER_ENTITIES
```

**Vulnerable RDFXMLParser.java getCompulsoryXmlFeatureSettings() (before patch):**
```java
public Collection<RioSetting<Boolean>> getCompulsoryXmlFeatureSettings() {
    Set<RioSetting<Boolean>> results = new HashSet<RioSetting<Boolean>>();
    results.add(XMLParserSettings.SECURE_PROCESSING);
    // Missing XXE protection settings
    return results;
}
```

**Fixed version (after patch):**
```java
// New settings in XMLParserSettings.java:
public static final RioSetting<Boolean> DISALLOW_DOCTYPE_DECL = new RioSettingImpl<Boolean>(
    "http://apache.org/xml/features/disallow-doctype-decl", "Disallow DOCTYPE declaration in document", true);

public static final RioSetting<Boolean> EXTERNAL_GENERAL_ENTITIES = new RioSettingImpl<Boolean>(
    "http://xml.org/sax/features/external-general-entities", "Include external general entities", false);

public static final RioSetting<Boolean> EXTERNAL_PARAMETER_ENTITIES = new RioSettingImpl<Boolean>(
    "http://xml.org/sax/features/external-parameter-entities", "Include external parameter entities", false);

// Updated getCompulsoryXmlFeatureSettings():
public Collection<RioSetting<Boolean>> getCompulsoryXmlFeatureSettings() {
    Set<RioSetting<Boolean>> results = new HashSet<RioSetting<Boolean>>();
    results.add(XMLParserSettings.SECURE_PROCESSING);
    results.add(XMLParserSettings.DISALLOW_DOCTYPE_DECL);        // Added
    results.add(XMLParserSettings.EXTERNAL_GENERAL_ENTITIES);    // Added
    results.add(XMLParserSettings.EXTERNAL_PARAMETER_ENTITIES);  // Added
    return results;
}
```

## CWE Classification
- **CWE-611**: Improper Restriction of XML External Entity Reference (XXE)
- **CWE-918**: Server-Side Request Forgery (SSRF)

## Vulnerability Description

This is a classic XML External Entity (XXE) injection vulnerability in Eclipse RDF4J's XML parser. The vulnerability exists in the RDF/XML and TriX parsers, which use SAX-based XML parsing without proper security configurations.

**Root Cause:**
The XML parser configuration in `XMLParserSettings.java` did not disable external entity processing by default. Specifically:
1. DOCTYPE declarations were allowed
2. External general entities were processed (default behavior)
3. External parameter entities were processed (default behavior)
4. The `LOAD_EXTERNAL_DTD` setting defaulted to `true`

**Attack Vector:**
An attacker can craft a malicious RDF/XML document containing DOCTYPE declarations with external entity references. When parsed, the XML parser attempts to resolve these external entities by making HTTP connections to attacker-controlled servers.

**Impact:**
- **Information Disclosure**: Access to local files via `file://` URIs
- **Server-Side Request Forgery (SSRF)**: Connections to internal/external servers
- **Denial of Service**: Billion Laughs attack, recursive entity expansion
- **Port Scanning**: Probing internal network services

**Exploitation:**
The POV demonstrates a basic XXE attack that triggers SSRF:
```xml
<!DOCTYPE rdf:RDF [
    <!ENTITY xxe SYSTEM "http://jazzer.example.com" >
]>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="http://example.org/foo/bar">
        <rdfs:label>&xxe;</rdfs:label>
    </rdf:Description>
</rdf:RDF>
```

When the parser encounters `&xxe;`, it attempts to fetch the content from `http://jazzer.example.com`, triggering the SSRF detection.

## POV Analysis

**File**: pov_0.blob (395 bytes)

The POV is a minimal XXE attack demonstrating SSRF:
- Defines an external entity `xxe` that references `http://jazzer.example.com`
- References the entity within an RDF label element
- The parser attempts to resolve the external entity, triggering an HTTP connection
- Jazzer's SSRF sanitizer detects and reports the attempted connection

This POV effectively demonstrates that the vulnerability allows arbitrary external HTTP connections, which can be used for:
- Exfiltrating sensitive data
- Accessing internal services
- Port scanning internal networks
- Credential theft

## Patch Analysis

**Patch File**: patch_0.diff (72,675 bytes)

The patch (GitHub PR #1146, commit b83147e2a80c4f196018eed8c466073b6c9fb627) comprehensively addresses the XXE vulnerability:

### Key Changes:

1. **New Security Settings in XMLParserSettings.java**:
   - Added `DISALLOW_DOCTYPE_DECL` (default: true) - Prevents DOCTYPE declarations entirely
   - Added `EXTERNAL_GENERAL_ENTITIES` (default: false) - Disables external general entity processing
   - Added `EXTERNAL_PARAMETER_ENTITIES` (default: false) - Disables external parameter entity processing
   - Changed `LOAD_EXTERNAL_DTD` default from `true` to `false`

2. **New Base Class XMLReaderBasedParser.java**:
   - Created a shared base class for XML-based parsers
   - Centralizes XML reader configuration and security settings
   - Ensures consistent XXE protection across all XML parsers

3. **Updated RDFXMLParser.java**:
   - Now extends `XMLReaderBasedParser`
   - Inherits the secure `getCompulsoryXmlFeatureSettings()` method
   - Applies XXE protection settings to the XML reader before parsing

4. **Updated TriXParser.java**:
   - Similar changes to extend `XMLReaderBasedParser`
   - Applies same XXE protections

5. **Updated AbstractSPARQLXMLParser.java**:
   - Added three new XXE protection settings to compulsory features

6. **Test Coverage**:
   - Added test files: `rdfxml-external-general-entity.rdf`, `rdfxml-external-param-entity.rdf`
   - Added test files: `trix-xxe-external-entity.trix`, `trix-xxe-external-param-entity.trix`
   - Updated test assertions to verify 25 supported settings (was 22)

### Defense-in-Depth Approach:
The patch implements multiple layers of protection:
- Disallows DOCTYPE entirely (strongest protection)
- Disables external general entities (prevents basic XXE)
- Disables external parameter entities (prevents parameter entity attacks)
- Disables external DTD loading (prevents DTD-based attacks)

This follows OWASP XXE Prevention Cheat Sheet recommendations.

## Recommendations

### Suggested CWEs:
- CWE-611 (primary)
- CWE-918 (secondary impact)

### Vulnerability Name:
"XXE Injection in RDF/XML Parser Leading to SSRF"

### Additional Notes:
- This is a well-documented 1-day vulnerability (CVE-2018-1000644)
- Fixed in RDF4J version 2.4.0 Milestone 2
- The vulnerability affects both RDFXMLParser and TriXParser
- A follow-up issue (#1202) was raised because the strict DOCTYPE restrictions broke compatibility with legitimate RDF sources (Wordnet, Pizza ontology)
- The vulnerability was publicly disclosed at https://0dd.zone/2018/08/05/rdf4j-XXE/