# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: WidocoOne
- **Vulnerability Type**: Path Traversal / Zip Slip (CWE-22)
- **Origin**: 1-day
- **Release Date**: 12/27/2022
- **CVE**: CVE-2022-4772
- **CVSS Score**: 7.4 (High)
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2022-4772
  - https://github.com/dgarijo/Widoco/pull/551
  - https://github.com/dgarijo/Widoco/commit/f2279b76827f32190adfa9bd5229b7d5a147fa92
  - https://security.snyk.io/vuln/SNYK-JAVA-COMGITHUBDGARIJO-3227637

## Crash Log Analysis
- **Error Type**: File path traversal
- **Crash Location**: widoco/WidocoUtils.java:269
- **Vulnerable Function**: `unZipIt`
- **DEDUP Token**: 9edcd163dc417f0e
- **Sanitizer Detection**: Jazzer FilePathTraversal sanitizer

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: /tmp/WidocoOne2583771890460405158/../jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.check(FilePathTraversal.java:346)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkFile(FilePathTraversal.java:304)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.checkObj(FilePathTraversal.java:288)
	at com.code_intelligence.jazzer.sanitizers.FilePathTraversal.processFileOutputStartHook(FilePathTraversal.java:256)
	at widoco.WidocoUtils.unZipIt(WidocoUtils.java:269)
	at com.aixcc.widoco.harnesses.one.WidocoOne.fuzz(WidocoOne.java:27)
	at com.aixcc.widoco.harnesses.one.WidocoOne.fuzzerTestOneInput(WidocoOne.java:18)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: Both crash_site and root_cause
- **File Path**: src/main/java/widoco/WidocoUtils.java
- **Function**: `unZipIt`
- **Line Range**: 256-256 (vulnerable line where File object is created without validation)
- **Column Range**: 1-100

### Code Context (Before Fix)
```java
public static void unZipIt(ZipInputStream zis, String outputFolder) {
    byte[] buffer = new byte[1024];
    try {
        ZipEntry ze = zis.getNextEntry();

        while (ze != null) {
            String fileName = ze.getName();
            File newFile = new File(outputFolder + File.separator + fileName);  // Line 256 - VULNERABLE
            // System.out.println("file unzip : "+ newFile.getAbsoluteFile());
            if (ze.isDirectory()) {
                String temp = newFile.getAbsolutePath();
                new File(temp).mkdirs();
            } else {
                String directory = newFile.getParent();
                if (directory != null) {
                    File d = new File(directory);
                    if (!d.exists()) {
                        d.mkdirs();
                    }
                }
                FileOutputStream fos = new FileOutputStream(newFile);  // Line 269 - Crash occurs here
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            ze = zis.getNextEntry();
        }
```

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23**: Relative Path Traversal
- **CWE-59**: Improper Link Resolution Before File Access ('Link Following')

## Vulnerability Description

This is a classic **Zip Slip vulnerability** (CVE-2022-4772) affecting Widoco versions up to 1.4.17. The vulnerability occurs in the `unZipIt` function in `src/main/java/widoco/WidocoUtils.java`.

### Root Cause
The function constructs file paths from ZIP entry names without proper validation:
```java
File newFile = new File(outputFolder + File.separator + fileName);
```

When processing a malicious ZIP file containing entries with relative path traversal sequences (e.g., `../jazzer-traversal`), the code creates files outside the intended extraction directory. This allows an attacker to:

1. Overwrite arbitrary files on the system
2. Plant malicious executables in sensitive locations
3. Potentially achieve remote code execution by overwriting configuration or executable files

### Attack Vector
The POV file (`pov_0.blob`) is a crafted ZIP archive containing a single entry named `../jazzer-traversal`. When this ZIP is processed by `unZipIt()`:

1. The function reads the entry name: `../jazzer-traversal`
2. Concatenates it with the output folder: `/tmp/WidocoOne2583771890460405158/../jazzer-traversal`
3. Attempts to create a FileOutputStream to this path
4. The Jazzer FilePathTraversal sanitizer detects the path escapes the intended directory
5. Throws `FuzzerSecurityIssueCritical` exception

### Why This is Critical
- **CVSS 7.4 (High)**: The vulnerability has significant impact
- **Arbitrary File Write**: Attackers can write files anywhere on the filesystem
- **Code Execution**: By overwriting executables or configuration files, attackers can achieve remote code execution
- **Wide Attack Surface**: Any application that processes untrusted ZIP files is vulnerable

## POV Analysis

The POV (`pov_0.blob`) is a minimal ZIP archive demonstrating the path traversal vulnerability:

```
Archive contents:
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-10-14 19:45   ../jazzer-traversal
```

**Key characteristics**:
- Single entry with relative path traversal: `../jazzer-traversal`
- Targets the parent directory of the extraction folder
- The Jazzer sanitizer successfully detects and reports the traversal attempt
- Entry name starts with `../` which allows escaping the intended extraction directory

## Patch Analysis

The patch makes two critical changes to fix the vulnerability:

### Change 1: Proper File Constructor Usage
**Before:**
```java
File newFile = new File(outputFolder + File.separator + fileName);
```

**After:**
```java
File newFile = new File(outputFolder, fileName);
```

This uses the two-argument File constructor which properly handles path separators across platforms.

### Change 2: Path Validation Guard (Critical Security Fix)
**Added:**
```java
if (!newFile.toPath().normalize().startsWith(outputFolder)) {
    throw new RuntimeException("Bad zip entry");
}
```

This validation:
1. Converts the File to a Path object
2. **Normalizes** the path (resolves `..`, `.`, and symbolic links)
3. Checks if the normalized path starts with the output folder
4. Throws an exception if the path escapes the intended directory

### Why the Fix Works
The normalization step is critical. Consider this example:
- Without normalization: `/tmp/WidocoOne/../jazzer-traversal` might pass a naive string check
- With normalization: `/tmp/WidocoOne/../jazzer-traversal` becomes `/tmp/jazzer-traversal`
- The `startsWith()` check then correctly identifies this as outside `/tmp/WidocoOne/`

The fix also prevents partial path traversal attacks where:
```java
"/usr/outnot".startsWith("/usr/out")  // Returns true (vulnerable)
```

By using Path API:
```java
Paths.get("/usr/outnot").startsWith(Paths.get("/usr/out"))  // Returns false (secure)
```

## Timeline
- **July 30, 2022**: Vulnerability reported by Jonathan Leitschuh
- **August 1, 2022**: Fix merged into Widoco develop branch
- **December 27, 2022**: CVE-2022-4772 published to NVD

## Recommendations

### For vuln.yaml Generation
- **Vulnerability Name**: "Zip Slip Path Traversal in unZipIt"
- **Suggested CWEs**: [CWE-22, CWE-23]
- **Origin**: 1-day
- **Release Date**: 12/27/2022
- **Crash Site Location**: src/main/java/widoco/WidocoUtils.java:269 (where FileOutputStream is created)
- **Root Cause Location**: src/main/java/widoco/WidocoUtils.java:256 (where File path is constructed without validation)
- **Note**: Both crash_site and root_cause are in the same function, but different lines. Line 256 is where the vulnerable path is created, line 269 is where the actual crash/detection occurs.

### Security Best Practices
1. Always validate and normalize file paths from untrusted sources
2. Use `Path.normalize()` and `startsWith()` checks for directory traversal prevention
3. Avoid string concatenation for path construction
4. Implement allowlists for permitted file names/extensions
5. Run with minimal filesystem permissions

---

**Analysis Complete**: This is a confirmed 1-day vulnerability (CVE-2022-4772) with official CVE entry, GitHub security fix, and multiple vulnerability database references.