I'll analyze the vulnerability for cpv_0 in the TikaOne harness. Let me start by examining the crash logs and then trace through to the vulnerable code.Now let me read the crash log to understand the vulnerability:Let me read the crash log in parts, focusing on the key information:Let me search for the actual error in the log:Perfect! I found the key information. Let me read more context around line 1660:Excellent! Now I have the full picture. Let me read the patch and POV to understand better:Perfect! Now let me examine the vulnerable source code:Let me find the TikaCLI.java file:Let me check the .oss-fuzz directory structure:Now let me check the build.sh to understand where the Tika source is:I see the source is built from the git repository. Let me check the git log to find the relevant commit and then examine the vulnerable code:Let me check out the base commit:Great! Now let me find and read the vulnerable TikaCLI.java file:Perfect! Now let me read the vulnerable code section:I need to see the part where URLDecoder is used. Let me check around line 1146-1148:Let me check the patched version to understand what was changed:Now I understand the vulnerability! Let me check the POV file more closely:Perfect! Now I have all the information I need. Let me also check line numbers more precisely by looking at both versions:Wait, I see an inconsistency. The patch file in the CPV directory shows URL decoding being moved BEFORE normalization, but the git diff shows it's being added AFTER. Let me re-read the patch file:I see! The patch in the CPV directory shows that the intermediate commit (4a8889c which added URLDecoder AFTER normalization) is vulnerable, and the fix is to move URLDecoder BEFORE normalization. So there are three states:

1. Base commit (8f1c3d9) - No URLDecoder at all
2. Intermediate commit (4a8889c) - URLDecoder AFTER normalization (VULNERABLE)
3. Fixed commit (7f2e3a1) - URLDecoder BEFORE normalization (FIXED)

Let me verify the intermediate commit state by reading the base commit in the patch:Let me get the code from the ref_commit (which should be the vulnerable state):I see! So the commit 7f2e3a1 is titled "Decode the file name when extracting embedded document". Now let me check what's between base and ref:So there's only one commit between them. Let me understand this better - the meta.yaml shows base_commit is 8f1c3d9 and ref_commit is 7f2e3a1. But the patch shows an intermediate state (4a8889c). Let me check the patch more carefully. Looking at the patch, the vulnerable code has URLDecoder AFTER normalization, and the fix moves it BEFORE. Let me understand the vulnerability better by checking what the base commit (8f1c3d9) looked like:So base commit has no URLDecoder. Now let me understand the CPV patches directory structure better. The patch_0.diff shows changes that fix cpv_0. Let me re-analyze:

The vulnerability scenario is:
1. Base (8f1c3d9): No URL decoding - Files with URL-encoded path separators are NOT decoded
2. Intermediate (vulnerable - this is what the patch is applied FROM): URLDecoder.decode() is called AFTER FilenameUtils.normalize()
3. Fixed (7f2e3a1): URLDecoder.decode() is called BEFORE FilenameUtils.normalize()

But wait, let me check if there's a commit between base and ref:Let me look at the actual diff from the git log to understand what 7f2e3a1 changed:Now I see the commit adds URLDecoder. Let me see the actual code change in the commit:Now I understand! The commit 7f2e3a1 adds URLDecoder.decode() AFTER FilenameUtils.normalize(). But the patch_0.diff shows that this is vulnerable and needs to be fixed by moving URLDecoder.decode() BEFORE FilenameUtils.normalize(). So the CPV is testing the vulnerable state (ref_commit 7f2e3a1) where URL decoding happens after normalization, and the patch fixes it. Let me verify my understanding by looking at what the patched state would look like. The vulnerability is clear now:

1. **Base commit (8f1c3d9)**: No URL decoding - filenames with URL-encoded sequences remain encoded, so path traversal with `..%2F` doesn't work
2. **Vulnerable commit (7f2e3a1 - ref_commit)**: URLDecoder.decode() AFTER FilenameUtils.normalize() - This is vulnerable because:
   - FilenameUtils.normalize() first processes the path as `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal`
   - Since `%2F` is not decoded yet, normalize doesn't recognize it as path separators
   - Then URLDecoder.decode() converts `%2F` to `/`, resulting in `./../../../../../jazzer-traversal`
   - This decoded path with `..` can traverse outside the extraction directory
3. **Fixed state (patch applied)**: URLDecoder.decode() BEFORE FilenameUtils.normalize() - This fixes it because:
   - First decode `..%2F` to `../`
   - Then FilenameUtils.normalize() can properly detect and handle/reject the path traversal

Now I have all the information needed. Let me create the vulnerability analysis report:

# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: TikaOne
- **Vulnerability Type**: Path Traversal / Directory Traversal
- **Severity**: High

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: File path traversal
- **Crash Location**: TikaCLI.java:1103 (parseEmbedded method)
- **Vulnerable Function**: `getOutputFile` in `FileEmbeddedDocumentExtractor` class
- **DEDUP Token**: 766e28c25b7cde1c

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
```

## Vulnerable Code Location
- **File Path**: tika-app/src/main/java/org/apache/tika/cli/TikaCLI.java
- **Function**: `getOutputFile` (private method in `FileEmbeddedDocumentExtractor` inner class)
- **Line Range**: 1119-1155 (vulnerable code in commit 7f2e3a1)
- **Critical Line**: Line 1147 (where URLDecoder.decode() is called AFTER normalization)

### Code Context (Vulnerable Version - Commit 7f2e3a1)
```java
private File getOutputFile(String name, Metadata metadata, MediaType contentType) {
    // ... [filename processing code] ...
    
    //defensively do this so that we don't get an exception
    //from FilenameUtils.normalize
    name = name.replaceAll("\u0000", " ");
    String normalizedName = FilenameUtils.normalize(name);  // Line 1132

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

    normalizedName = URLDecoder.decode(normalizedName, UTF_8);  // Line 1147 - VULNERABLE!

    File outputFile = new File(extractDir, normalizedName);
    // ... [remaining code] ...
}
```

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23**: Relative Path Traversal
- **CWE-706**: Use of Incorrectly-Resolved Name or Reference

## Vulnerability Description

This vulnerability is a **path traversal** flaw caused by **incorrect order of operations** when processing embedded file names during archive extraction in Apache Tika.

### Root Cause

The vulnerability exists because `URLDecoder.decode()` is called **AFTER** `FilenameUtils.normalize()`. This allows an attacker to bypass path normalization by using URL-encoded path separators:

1. A malicious archive contains an embedded file with a URL-encoded path traversal name like `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal`

2. `FilenameUtils.normalize()` processes the filename first, but doesn't recognize `%2F` (URL-encoded `/`) as a path separator, so it treats the entire string as a safe filename

3. `URLDecoder.decode()` then decodes `%2F` to `/`, transforming the filename into `./../../../../../jazzer-traversal`

4. This decoded path containing `../` sequences is used directly in `new File(extractDir, normalizedName)`, allowing the attacker to write files outside the intended extraction directory

### Impact

- **Arbitrary File Write**: An attacker can write files to arbitrary locations on the filesystem where the Tika process has write permissions
- **Code Execution**: By writing malicious files to sensitive locations (e.g., cron jobs, startup scripts, web server directories), an attacker could achieve remote code execution
- **Data Integrity**: Existing files could be overwritten, leading to denial of service or data corruption
- **Privilege Escalation**: If Tika runs with elevated privileges, this could lead to system compromise

## POV Analysis

The proof-of-vulnerability test case (`pov_0.blob`) is a ZIP archive containing:
- **Filename**: `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal`
- **Format**: ZIP archive with stored (uncompressed) entry

When this archive is processed by the vulnerable Tika code:
1. The entry name `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal` passes through normalization unchanged
2. After URL decoding, it becomes `./../../../../../jazzer-traversal`
3. This triggers the path traversal detection in Jazzer's security hooks
4. The file would be written 5 directories above the extraction directory

The log shows:
```
Extracting '..%2F..%2F..%2F..%2F..%2Fjazzer-traversal' (application/octet-stream) to ./../../../../../jazzer-traversal
```

## Patch Analysis

The patch (`patch_0.diff`) fixes the vulnerability by **reordering the operations**:

### Fix Applied
```diff
-            String normalizedName = FilenameUtils.normalize(name);
+
+            String normalizedName = URLDecoder.decode(name, UTF_8);
+            normalizedName = FilenameUtils.normalize(normalizedName);

             // ... [null checks and prefix handling] ...

-            normalizedName = URLDecoder.decode(normalizedName, UTF_8);
-
             File outputFile = new File(extractDir, normalizedName);
```

### Why This Fixes The Vulnerability

By calling `URLDecoder.decode()` **BEFORE** `FilenameUtils.normalize()`:

1. URL-encoded sequences like `%2F` are decoded to `/` first
2. `FilenameUtils.normalize()` can then properly detect and handle/remove path traversal sequences (`../`)
3. The resulting normalized path cannot escape the extraction directory

**Example flow after patch:**
- Input: `..%2F..%2F..%2F..%2F..%2Fjazzer-traversal`
- After URLDecoder: `./../../../../../jazzer-traversal`
- After FilenameUtils.normalize(): Returns `null` or a safe path (path traversal removed)
- Result: File extraction is prevented or uses a safe fallback name

## Recommendations

### Suggested CWEs
- **Primary**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Secondary**: CWE-23 (Relative Path Traversal)
- **Related**: CWE-706 (Use of Incorrectly-Resolved Name or Reference)

### Vulnerability Name
**"Apache Tika Path Traversal via URL-Encoded Filenames in Archive Extraction"**

### Additional Security Measures
Beyond applying the patch, consider:
1. **Input Validation**: Reject filenames containing encoded path separators
2. **Sandboxing**: Run Tika extraction in a sandboxed environment with restricted filesystem access
3. **Path Verification**: After all transformations, verify the final path is within the extraction directory using canonical path checks
4. **Security Testing**: Add fuzzing tests with various encoding combinations (double encoding, mixed encoding, etc.)