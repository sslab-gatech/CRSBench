# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: JenkinsThree
- **Vulnerability Type**: File Path Traversal
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: File path traversal
- **Crash Location**: hudson/PluginManager.java:1640
- **Vulnerable Function**: doPerformUpload
- **DEDUP Token**: c53161604d781854

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal: /tmp/plugins/../../home/jazzer-traversal
	at com.code_intelligence.jazzer.sanitizers.FileSystemTraversal.maybeReport(FileSystemTraversal.java:262)
	at com.code_intelligence.jazzer.sanitizers.FileSystemTraversal.maybeReport(FileSystemTraversal.java:243)
	at com.code_intelligence.jazzer.sanitizers.FileSystemTraversal.processFileOutputStartHook(FileSystemTraversal.java:197)
	at hudson.PluginManager.doPerformUpload(PluginManager.java:1640)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.testPlugin(JenkinsThree.java:352)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzz(JenkinsThree.java:91)
	at com.aixcc.jenkins.harnesses.three.JenkinsThree.fuzzerTestOneInput(JenkinsThree.java:76)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: jenkins/core/src/main/java/hudson/PluginManager.java
- **Function**: doPerformUpload
- **Line Range**: 1638-1638
- **Column Range**: 13-72

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: jenkins/core/src/main/java/hudson/PluginManager.java
- **Function**: doPerformUpload
- **Line Range**: 1640-1640
- **Column Range**: 13-57

### Code Context

**Vulnerable code (before patch):**
```java
@RequirePOST
public HttpResponse doPerformUpload(StaplerRequest req) throws IOException, ServletException {
    try {
        File tmpDir = Files.createTempDirectory("uploadDir").toFile();
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory(DiskFileItemFactory.DEFAULT_SIZE_THRESHOLD, tmpDir));
        List<FileItem> items = upload.parseRequest(req);

        if (!req.hasParameter("uploadId")) {
            return hudson.util.HttpResponses.errorJSON("No upload id specified");
        }

        int reqUploadId;
        try {
            reqUploadId = Integer.parseInt(req.getParameter("uploadId"));
        } catch (NumberFormatException e) {
            return hudson.util.HttpResponses.errorJSON(e.getMessage());
        }
        if (this.uploadId != reqUploadId) {
            return hudson.util.HttpResponses.errorJSON("Wrong upload id");
        }

        FileItem fileItem = items.get(0);
        File uploadDir = new File("/tmp/plugins");
        uploadDir.mkdirs();
        File uploadedFile = new File(uploadDir, req.getParameter("uploadPath"));  // LINE 1638 - ROOT CAUSE

        FileOutputStream fos = new FileOutputStream(uploadedFile);  // LINE 1640 - CRASH SITE
        fos.write(fileItem.get());

        JSONObject response = new JSONObject();
        response.put("uploaded", true);
        response.put("path", uploadedFile.getAbsolutePath());
        return hudson.util.HttpResponses.okJSON(response);
    } catch (Exception e) {
        throw new ServletException(e);
    }
}
```

**Attack scenario:**
The vulnerability occurs when an attacker provides a malicious `uploadPath` parameter containing path traversal sequences (e.g., `../../home/jazzer-traversal`). The code directly concatenates this user-controlled input with the base directory without validation, allowing files to be written outside the intended `/tmp/plugins` directory.

## CWE Classification
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-23**: Relative Path Traversal

## Vulnerability Description

This is a **path traversal vulnerability** in the Jenkins plugin upload functionality. The `doPerformUpload` method accepts a file upload request and saves the uploaded file to a location determined by concatenating a base directory (`/tmp/plugins`) with a user-supplied `uploadPath` parameter.

**Root Cause (Line 1638):**
The vulnerability exists because the code directly uses unsanitized user input (`req.getParameter("uploadPath")`) to construct a file path:
```java
File uploadedFile = new File(uploadDir, req.getParameter("uploadPath"));
```

**Crash Site (Line 1640):**
When the malicious path is used to create a `FileOutputStream`, the Jazzer security sanitizer detects the path traversal attempt and reports it as a security issue:
```java
FileOutputStream fos = new FileOutputStream(uploadedFile);
```

**Attack Vector:**
An attacker can provide a `uploadPath` parameter like `../../home/jazzer-traversal` which, when combined with `/tmp/plugins`, results in a file path that escapes the intended directory and allows writing files to arbitrary locations on the filesystem (e.g., `/home/jazzer-traversal`).

**Impact:**
- **Arbitrary file write**: Attackers can write files to any location on the Jenkins controller filesystem where the Jenkins process has write permissions
- **Code execution**: By overwriting configuration files, plugins, or executable scripts, attackers could achieve remote code execution
- **Data integrity**: Critical system or application files could be overwritten or corrupted

## POV Analysis

The POV file (`pov_0.blob`) is a 272-byte test input that triggers the vulnerability by providing:
- A valid `uploadId` parameter
- A malicious `uploadPath` parameter containing path traversal sequences (`../../home/jazzer-traversal`)
- File upload data

When processed by the vulnerable `doPerformUpload` method, this input causes the application to attempt writing a file outside the intended `/tmp/plugins` directory, which is detected by the Jazzer FileSystemTraversal sanitizer.

## Patch Analysis

The patch introduces comprehensive path traversal protection:

**Changes made:**
1. **Null check**: Added validation to ensure `uploadPath` parameter is provided
2. **Path canonicalization**: Both the base directory and final destination paths are canonicalized to resolve symbolic links and relative paths
3. **Path containment check**: Verifies that the canonical destination path either equals or starts with the canonical base directory path followed by a file separator

**Patch code:**
```java
String uploadPath = req.getParameter("uploadPath");
if (uploadPath == null) {
    return hudson.util.HttpResponses.errorJSON("No upload path specified");
}
File uploadedFile = new File(uploadDir, uploadPath);
String canonicalDir = uploadDir.getCanonicalPath();
String canonicalDest = uploadedFile.getCanonicalPath();
if (!canonicalDest.equals(canonicalDir) && !canonicalDest.startsWith(canonicalDir + File.separator)) {
    return hudson.util.HttpResponses.errorJSON("Invalid upload path");
}
```

This fix ensures that path traversal sequences like `../` are resolved, and the final destination is validated to be within the intended upload directory.

## Recommendations
- **Suggested CWEs**: [CWE-22, CWE-23]
- **Vulnerability name**: Path Traversal in Jenkins Plugin Upload

---

**Analysis Classification:**
- **Origin determination**: Searched for known CVEs/advisories for `hudson.PluginManager.doPerformUpload` path traversal, found no exact matches. Git history shows this vulnerability was introduced in synthetic commits for benchmark purposes. Therefore, classified as **synthetic**.
- **Locations**: Two distinct locations identified:
  - **root_cause** (line 1638): Where unsanitized user input is used to construct file path
  - **crash_site** (line 1640): Where the malicious path triggers the FileOutputStream and security detection