# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: ZTZIPOne
- **Vulnerability Type**: Path Traversal (Zip Slip)
- **Origin**: 1-day
- **Release Date**: 07/25/2018
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1002201
  - https://security.snyk.io/vuln/SNYK-JAVA-ORGZEROTURNAROUND-31681
  - https://github.com/zeroturnaround/zt-zip/commit/759b72f33bc8f4d69f84f09fcb7f010ad45d6fff

## Crash Log Analysis
- **Error Type**: File path traversal (Jazzer sanitizer detection)
- **Crash Location**: Detected by Jazzer's FilePathTraversal sanitizer
- **Vulnerable Function**: `org.zeroturnaround.zip.ZipUtil$Unpacker.process()`
- **DEDUP Token**: 5613928bc862f49b

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: /tmp/ztzip-13778327023876392046/../../jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.check(FilePathTraversal.java:346)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkFile(FilePathTraversal.java:304)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkObj(FilePathTraversal.java:288)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.processFileOutputStartHook(FilePathTraversal.java:256)
	at org.zeroturnaround.zip.commons.FileUtils.copy(FileUtils.java:54)
	at org.zeroturnaround.zip.ZipUtil$Unpacker.process(ZipUtil.java:1163)
	at org.zeroturnaround.zip.ZipUtil.iterate(ZipUtil.java:712)
	at org.zeroturnaround.zip.ZipUtil.unpack(ZipUtil.java:1096)
	at org.zeroturnaround.zip.ZipUtil.unpack(ZipUtil.java:1045)
	at com.aixcc.ztzip.harnesses.one.ZTZIPOne.fuzz(ZTZIPOne.java:63)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/main/java/org/zeroturnaround/zip/ZipUtil.java
- **Function**: `ZipUtil$Unpacker.process`
- **Line Range**: 1163-1163
- **Column Range**: 1-40

### Location 2 (root_cause - Unpacker.process)
- **Type**: root_cause
- **File Path**: src/main/java/org/zeroturnaround/zip/ZipUtil.java
- **Function**: `ZipUtil$Unpacker.process`
- **Line Range**: 1152-1152
- **Column Range**: 1-50

### Location 3 (root_cause - BackslashUnpacker.process for backslash paths)
- **Type**: root_cause
- **File Path**: src/main/java/org/zeroturnaround/zip/ZipUtil.java
- **Function**: `ZipUtil$BackslashUnpacker.process`
- **Line Range**: 1220-1226
- **Column Range**: 1-50

### Code Context (Unpacker.process - vulnerable)
```java
public void process(InputStream in, ZipEntry zipEntry) throws IOException {
  String name = mapper.map(zipEntry.getName());
  if (name != null) {
    File file = new File(outputDir, name);  // Line 1152 - No validation of name
    if (zipEntry.isDirectory()) {
      FileUtils.forceMkdir(file);
    }
    else {
      FileUtils.forceMkdir(file.getParentFile());
      
      if (log.isDebugEnabled() && file.exists()) {
        log.debug("Overwriting file '{}'.", zipEntry.getName());
      }
      
      FileUtils.copy(in, file);  // Line 1163 - Writes to unvalidated path
    }
    
    ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
    if (permissions != null) {
      ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
    }
  }
}
```

### Code Context (BackslashUnpacker.process - vulnerable)
```java
public void process(InputStream in, ZipEntry zipEntry) throws IOException {
  String name = mapper.map(zipEntry.getName());
  if (name != null) {
    if (name.indexOf('\\') != -1) {
      File parentDirectory = outputDir;
      String[] dirs = name.split("\\\\");
      
      for (int i = 0; i < dirs.length - 1; i++) {
        File file = new File(parentDirectory, dirs[i]);
        if (!file.exists()) {
          FileUtils.forceMkdir(file);
        }
        parentDirectory = file;
      }
      File destFile = new File(parentDirectory, dirs[dirs.length - 1]);  // Line 1220
      FileUtils.copy(in, destFile);  // Line 1221 - Writes without validation
    }
    else {
      File destFile = new File(outputDir, name);  // Line 1225
      FileUtils.copy(in, destFile);  // Line 1226 - Writes without validation
    }
  }
}
```

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-29**: Path Traversal: '\..\filename'

## Vulnerability Description

This is a **Zip Slip vulnerability** (CVE-2018-1002201), a widespread arbitrary file write vulnerability affecting the zt-zip library version 1.12 and earlier. The vulnerability exists in the `ZipUtil.unpack()` method and its internal `Unpacker` and `BackslashUnpacker` classes.

**Root Cause**: The vulnerability occurs because the code directly concatenates the ZIP entry filename with the target output directory without validating that the resulting path stays within the intended extraction directory. A malicious ZIP archive can contain entries with path traversal sequences (e.g., `../../evil.sh`), causing files to be written outside the target directory.

**Attack Vector**: An attacker creates a specially crafted ZIP file where entry names contain relative path components like `../`. When the vulnerable `ZipUtil.unpack()` method extracts these entries:
1. It calls `mapper.map(zipEntry.getName())` to get the entry name
2. It constructs a `File` object via `new File(outputDir, name)` without validation
3. It writes the entry content to this unvalidated path via `FileUtils.copy(in, file)`

**Impact**: The attacker can:
- Write files to arbitrary locations on the filesystem
- Overwrite critical system files, configuration files, or executables
- Achieve remote code execution by overwriting scripts or binaries that are later executed
- Access sensitive directories outside the intended extraction folder

**Example**: If extracting to `/tmp/ztzip-12345/` and a ZIP entry has the name `../../jazzer-traversal`, the final path becomes `/tmp/jazzer-traversal`, escaping the intended directory.

This vulnerability was part of the widespread Zip Slip disclosure by Snyk Security Research Team in 2018, affecting thousands of projects across multiple programming languages.

## POV Analysis

The POV file (`pov_0.blob`) contains a specially crafted ZIP archive that exploits this path traversal vulnerability:

**POV Structure** (hex dump analysis):
```
00000000: 0000 0001 0000 0010 504b 0304 ...  (harness count/picker + ZIP magic)
00000020: ...2e2e 2f2e 2e2f 6a61 7a7a        (../../jazz)
00000030: 6572 2d74 7261 7665 7273 616c     (er-traversal)
```

**Key Elements**:
1. **Harness format**: The POV starts with count (1) and picker (16) indicating `ZipUtil.unpack()` test case
2. **ZIP magic**: `PK\x03\x04` indicates valid ZIP file format
3. **Malicious path**: The ZIP entry name is `../../jazzer-traversal`, designed to escape the temporary extraction directory
4. **Detection**: Jazzer's FilePathTraversal sanitizer detects the attempt to write to `/tmp/ztzip-13778327023876392046/../../jazzer-traversal`, which resolves to `/tmp/jazzer-traversal` outside the intended directory

The POV successfully triggers the vulnerability, causing the Jazzer sanitizer to raise a `FuzzerSecurityIssueCritical` exception with the message "File path traversal: /tmp/ztzip-13778327023876392046/../../jazzer-traversal".

## Patch Analysis

The patch (`patch_0.diff`) implements validation checks at three critical locations in `ZipUtil.java` to prevent path traversal attacks:

**Fix Strategy**: Add canonical path validation before any file write operation:

```java
if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
  throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
}
```

**Three Patched Locations**:

1. **Unpacker.process()** (line ~1152): After `File file = new File(outputDir, name);`, validates before processing directory or file
2. **BackslashUnpacker.process()** (line ~1220): After constructing `destFile` for backslash-separated paths
3. **BackslashUnpacker.process()** (line ~1225): After constructing `destFile` for top-level files

**Validation Logic**:
- **First check**: `name.indexOf("..")` - Quick detection of potential traversal sequences
- **Second check**: `!file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())` - Ensures the resolved canonical path stays within the target directory
- **Action**: Throws `ZipException` and prevents file extraction if validation fails

**Why It Works**:
- `getCanonicalPath()` resolves all relative components (`.`, `..`) and symlinks to absolute paths
- The `startsWith()` check ensures the final path is within the intended output directory tree
- This prevents not just `..` but also other path manipulation techniques (symlinks, multiple slashes, etc.)

The fix was implemented on April 26, 2018, by the zt-zip maintainers in response to the Snyk Security Research Team's disclosure, and was released in version 1.13.

## Recommendations

- **Suggested CWEs**: [CWE-22, CWE-29]
- **Vulnerability Name**: Zip Slip - Path Traversal in ZIP Extraction
- **Severity**: High/Critical (allows arbitrary file write and potential remote code execution)
- **Fix Version**: Upgrade to zt-zip version 1.13 or later