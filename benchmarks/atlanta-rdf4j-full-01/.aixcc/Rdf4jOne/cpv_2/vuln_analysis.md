# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: Rdf4jOne
- **Vulnerability Type**: File Path Traversal (Zip Slip)
- **Origin**: 1-day
- **Release Date**: 12/19/2018
- **References**: 
  - CVE-2018-20227: https://nvd.nist.gov/vuln/detail/cve-2018-20227
  - GitHub Issue: https://github.com/eclipse/rdf4j/issues/1210
  - Patch PR: https://github.com/eclipse/rdf4j/pull/1211

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: File path traversal
- **Crash Location**: org.eclipse.rdf4j.common.io.IOUtil.writeStream (IOUtil.java:387)
- **Vulnerable Function Chain**: 
  - `ZipUtil.extract()` → `ZipUtil.writeEntry()` → `IOUtil.writeStream()`
- **DEDUP Token**: be397ef28856c8b6

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: /tmp/rdf4j-extract-5984858285590719679/../../../../jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.check(FilePathTraversal.java:346)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkFile(FilePathTraversal.java:304)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkObj(FilePathTraversal.java:288)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.processFileOutputStartHook(FilePathTraversal.java:256)
	at org.eclipse.rdf4j.common.io.IOUtil.writeStream(IOUtil.java:387)
	at org.eclipse.rdf4j.common.io.ZipUtil.writeEntry(ZipUtil.java:107)
	at org.eclipse.rdf4j.common.io.ZipUtil.extract(ZipUtil.java:78)
	at com.aixcc.rdf4j.harnesses.one.Rdf4jOne.extract(Rdf4jOne.java:78)
	at com.aixcc.rdf4j.harnesses.one.Rdf4jOne.fuzz(Rdf4jOne.java:44)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: util/src/main/java/org/eclipse/rdf4j/common/io/ZipUtil.java
- **Function**: writeEntry
- **Line Range**: 97-97
- **Column Range**: 1-46

The root cause is at line 97 where the `File` object is created without validating that the resulting path stays within the destination directory:
```java
File outFile = new File(destDir, entry.getName());
```

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: util/src/main/java/org/eclipse/rdf4j/common/io/IOUtil.java
- **Function**: writeStream
- **Line Range**: 387-387
- **Column Range**: 1-46

The crash is detected at line 387 when attempting to write the file:
```java
FileOutputStream out = new FileOutputStream(file);
```

### Code Context (Root Cause)
From `ZipUtil.java` lines 94-113:
```java
public static void writeEntry(ZipFile zipFile, ZipEntry entry, File destDir)
    throws IOException
{
    File outFile = new File(destDir, entry.getName()); // VULNERABLE LINE 97
    
    if (entry.isDirectory()) {
        outFile.mkdirs();
    }
    else {
        outFile.getParentFile().mkdirs();
        
        InputStream in = zipFile.getInputStream(entry);
        try {
            IOUtil.writeStream(in, outFile); // This triggers the sanitizer at line 107
        }
        finally {
            in.close();
        }
    }
}
```

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23**: Relative Path Traversal

## Vulnerability Description

This is a classic "Zip Slip" vulnerability (CVE-2018-20227) in the Eclipse RDF4J library version 2.4.2. The vulnerability exists in the `ZipUtil.writeEntry()` method which extracts entries from ZIP archives without validating that the entry names don't contain path traversal sequences.

**Root Cause**: At line 97 of `ZipUtil.java`, the code creates a `File` object by concatenating the destination directory with the entry name from the ZIP file:
```java
File outFile = new File(destDir, entry.getName());
```

If the `entry.getName()` contains path traversal sequences like `../../../../malicious-file`, the resulting `outFile` path will escape the intended `destDir` directory, allowing an attacker to write files to arbitrary locations on the filesystem.

**Attack Vector**: An attacker can craft a malicious ZIP file with entries containing relative path traversal sequences (e.g., `../../../../jazzer-traversal`). When RDF4J extracts this ZIP file, it will write files outside the intended extraction directory, potentially overwriting critical system files or placing malicious files in sensitive locations.

**Impact**: This vulnerability has a CVSS v3.1 score of 7.5 (HIGH), with high integrity impact. An attacker can:
- Overwrite arbitrary files on the system
- Plant malicious files in sensitive directories
- Potentially achieve code execution if they can overwrite executable files or configuration files

## POV Analysis

The POV file (`pov_0.blob`) contains a crafted input that triggers the vulnerability. Examining the hexdump:

```
00000000  00 00 00 03 00 00 00 01  2e 2e 2f 2e 2e 2f 2e 2e  |........../../..|
00000010  2f 2e 2e 2f 6a 61 7a 7a  65 72 2d 74 72 61 76 65  |/../jazzer-trave|
00000020  72 73 61 6c                                       |rsal|
```

The POV contains the path traversal string `../../../../jazzer-traversal`, which attempts to escape the temporary extraction directory and write a file at `/tmp/rdf4j-extract-5984858285590719679/../../../../jazzer-traversal`. This demonstrates the path traversal attack successfully.

## Patch Analysis

The patch (from PR #1211, commit df15a4d7a8f2789c043b27c9eafe1b30316cfa79) fixes the vulnerability by adding a validation check before processing the entry:

**Fix location**: `util/src/main/java/org/eclipse/rdf4j/common/io/ZipUtil.java`, lines 99-101 (in patched version)

```java
if (! outFile.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
    throw new IOException("Zip entry outside destination directory: " + entry.getName());
}
```

**How it works**:
1. Converts both the output file path and destination directory to canonical paths (resolving `..` and symbolic links)
2. Checks if the canonical path of the output file starts with the canonical path of the destination directory
3. If the output file path escapes the destination directory, throws an IOException

This ensures that any entry with path traversal sequences is rejected before file creation, preventing the Zip Slip attack.

## Origin Verification

This vulnerability is confirmed as a **1-day** (real-world vulnerability):
1. ✅ **Official CVE assigned**: CVE-2018-20227
2. ✅ **Exact function match**: The patch modifies `ZipUtil.writeEntry()` which is the exact vulnerable function
3. ✅ **Same vulnerability type**: Directory traversal via ZIP entry names
4. ✅ **Same location**: `org.eclipse.rdf4j.common.io.ZipUtil` class
5. ✅ **Official reference exists**: GitHub issue #1210, NVD entry, and patch PR #1211
6. ✅ **Published date**: December 19, 2018

## Recommendations
- **Suggested CWEs**: [CWE-22, CWE-23]
- **Vulnerability name**: Zip Slip Path Traversal in RDF4J ZipUtil
- **Severity**: HIGH (CVSS 7.5)
- **Origin**: 1-day (CVE-2018-20227)
- **Release Date**: 12/19/2018