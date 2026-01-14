# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: TikaOne
- **Vulnerability Type**: File Path Traversal (URL-encoded)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: N/A (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: `com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal`
- **Crash Location**: `org.apache.tika.cli.TikaCLI$FileEmbeddedDocumentExtractor.parseEmbedded` (line 1103)
- **Vulnerable Function**: `getOutputFile` (called from `parseEmbedded`)
- **DEDUP Token**: `766e28c25b7cde1c`

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: ./../../../../../jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.check(FilePathTraversal.java:346)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkFile(FilePathTraversal.java:304)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkObj(FilePathTraversal.java:288)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.processFileOutputStartHook(FilePathTraversal.java:256)
	at org.apache.tika.cli.TikaCLI$FileEmbeddedDocumentExtractor.parseEmbedded(TikaCLI.java:1103)
	at org.apache.tika.parser.pkg.PackageParser.parseEntry(PackageParser.java:481)
	at org.apache.tika.parser.pkg.PackageParser.parseEntries(PackageParser.java:386)
	at org.apache.tika.parser.pkg.PackageParser._parse(PackageParser.java:336)
	at org.apache.tika.parser.pkg.PackageParser.parse(PackageParser.java:259)
	at org.apache.tika.parser.CompositeParser.parse(CompositeParser.java:298)
	at org.apache.tika.parser.CompositeParser.parse(CompositeParser.java:298)
	at org.apache.tika.parser.AutoDetectParser.parse(AutoDetectParser.java:204)
	at org.apache.tika.cli.TikaCLI$OutputType.process(TikaCLI.java:1047)
	at org.apache.tika.cli.TikaCLI.process(TikaCLI.java:478)
	at org.apache.tika.cli.TikaCLI.main(TikaCLI.java:245)
	at com.aixcc.tika.harnesses.one.TikaOne.fuzzerTestOneInput(TikaOne.java:29)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: tika-app/src/main/java/org/apache/tika/cli/TikaCLI.java
- **Function**: parseEmbedded
- **Line Range**: 1103-1103
- **Column Range**: 1-80

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: tika-app/src/main/java/org/apache/tika/cli/TikaCLI.java
- **Function**: getOutputFile
- **Line Range**: 1133-1148
- **Column Range**: 1-80

### Code Context

**Crash Site (parseEmbedded at line 1103):**
```java
File outputFile = getOutputFile(name, metadata, contentType);
// ... validation code ...
try (FileOutputStream os = new FileOutputStream(outputFile)) {  // Line 1103 - Crash site
    if (embeddedStreamTranslator.shouldTranslate(inputStream, metadata)) {
        try (InputStream translated = embeddedStreamTranslator.translate(inputStream, metadata)) {
            IOUtils.copy(translated, os);
        }
    } else {
        IOUtils.copy(inputStream, os);
    }
}
```

**Root Cause (getOutputFile, vulnerable lines 1133-1148):**
```java
private File getOutputFile(String name, Metadata metadata, MediaType contentType) {
    // ... initial processing ...
    
    //defensively do this so that we don't get an exception
    //from FilenameUtils.normalize
    name = name.replaceAll("\u0000", " ");
    String normalizedName = FilenameUtils.normalize(name);  // Line 1133 - Normalizes BEFORE decoding

    if (normalizedName == null) {
        normalizedName = FilenameUtils.getName(name);
    }

    if (normalizedName == null) {
        normalizedName = "file" + count++ + ext;
    }
    //strip off initial C:/ or ~/ or /
    int prefixLength = FilenameUtils.getPrefixLength(normalizedName);
    if (prefixLength > -1) {
        normalizedName = normalizedName.substring(prefixLength);
    }

    normalizedName = URLDecoder.decode(normalizedName, UTF_8);  // Line 1148 - VULNERABILITY: Decodes AFTER normalization
    
    File outputFile = new File(extractDir, normalizedName);  // Line 1150 - Creates file with traversal path
    // ...
}
```

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23**: Relative Path Traversal
- **CWE-73**: External Control of File Name or Path

## Vulnerability Description

This vulnerability is a **URL-encoded path traversal** flaw in Apache Tika's command-line interface (TikaCLI). The issue occurs when extracting embedded files from archives (like ZIP files).

### Root Cause

The vulnerability exists in the `getOutputFile()` method within the `FileEmbeddedDocumentExtractor` inner class. The problematic code flow is:

1. **Line 1133**: The filename is normalized using `FilenameUtils.normalize(name)` to remove path traversal sequences like `../`
2. **Line 1148**: **AFTER** normalization, the filename is URL-decoded using `URLDecoder.decode(normalizedName, UTF_8)`
3. **Line 1150**: The decoded (and potentially malicious) path is used to create a `File` object

### Attack Vector

An attacker can craft a malicious archive (e.g., ZIP file) containing an embedded file with a URL-encoded path traversal payload in its filename, such as:
- `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal`

When processed:
1. The normalization step sees `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal` (literally these characters, not path separators)
2. Normalization does nothing because `%2F` is not recognized as a path separator
3. URL decoding converts `%2F` → `/`, resulting in `../../../../../jazzer-traversal`
4. This decoded path is then used to create a file, allowing write access outside the intended extract directory

### Impact

- **Arbitrary File Write**: Attackers can write files to arbitrary locations on the filesystem
- **File Overwrite**: Existing files can be overwritten with malicious content
- **Remote Code Execution**: By overwriting executables or configuration files
- **Denial of Service**: By overwriting critical system files

## POV Analysis

The proof-of-vulnerability is a malicious ZIP file containing:
- **File Type**: ZIP archive (232 bytes)
- **Embedded Filename**: `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal` (URL-encoded path traversal)
- **Decoded Path**: `../../../../../jazzer-traversal` (traverses 5 directories up)

The POV successfully triggers the Jazzer security sanitizer, which detects the path traversal attempt when Tika tries to extract the file to a location outside the designated extraction directory.

## Patch Analysis

The patch fixes the vulnerability by **reversing the order of operations**:

**Before (Vulnerable):**
```java
String normalizedName = FilenameUtils.normalize(name);        // Normalize FIRST
// ... other processing ...
normalizedName = URLDecoder.decode(normalizedName, UTF_8);    // Decode SECOND
```

**After (Fixed):**
```java
String normalizedName = URLDecoder.decode(name, UTF_8);       // Decode FIRST
normalizedName = FilenameUtils.normalize(normalizedName);     // Normalize SECOND
```

By URL-decoding **before** normalization:
1. `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal` is decoded to `../../../../../jazzer-traversal`
2. `FilenameUtils.normalize()` then removes the `../` traversal sequences
3. The resulting path is safe and contained within the extraction directory

### Related Vulnerabilities

This vulnerability is conceptually related to **CVE-2018-11762** (Apache Tika path traversal with absolute paths), but this specific variant involving URL-encoded traversal sequences appears to be a **synthetic vulnerability** created for this benchmark, as no exact public CVE was found documenting this specific URLDecoder ordering issue in Tika.

## Recommendations

- **Suggested CWEs**: [CWE-22, CWE-23, CWE-73]
- **Vulnerability Name**: "URL-Encoded Path Traversal in TikaCLI Embedded File Extraction"
- **Severity**: High (allows arbitrary file write/overwrite)
- **Fix Applied**: Reorder URL decoding to occur before path normalization

---

**Analysis Complete**: This is a synthetic path traversal vulnerability demonstrating the security risks of incorrect input sanitization order when processing filenames from untrusted sources.