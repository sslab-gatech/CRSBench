# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: GeonetworkOneFDP
- **Vulnerability Type**: OS Command Injection
- **Origin**: 1-day
- **CVE**: CVE-2021-28398
- **Release Date**: 09/05/2022
- **Severity**: Moderate
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-28398
  - https://github.com/geonetwork/core-geonetwork/security/advisories/GHSA-cf8p-c88c-h9jf

## Crash Log Analysis
- **Error Type**: `com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection`
- **Detection Location**: Line 530 in crash log
- **Detection Method**: Jazzer sanitizer hook (OsCommandInjection.kt)
- **Vulnerable Function**: `runBeforeScript()`
- **Crash Location**: `LocalFilesystemHarvester.java:242`
- **DEDUP Token**: `256db4f5fb119030`

### Stack Trace
The vulnerability is triggered through the following call chain:
```
at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:60)
at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
at org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemHarvester.runBeforeScript(LocalFilesystemHarvester.java:242)
at org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemHarvester.doHarvest(LocalFilesystemHarvester.java:228)
at com.aixcc.geonetwork.harnesses.one.GeonetworkOneFDP.fuzz(GeonetworkOneFDP.java:92)
at com.aixcc.geonetwork.harnesses.one.GeonetworkOneFDP.fuzzerTestOneInput(GeonetworkOneFDP.java:75)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: `harvesters/src/main/java/org/fao/geonet/kernel/harvest/harvester/localfilesystem/LocalFilesystemHarvester.java`
- **Function**: `runBeforeScript()`
- **Line Range**: 239-242
- **Description**: The location where `ProcessBuilder.start()` is called with attacker-controlled data

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: `harvesters/src/main/java/org/fao/geonet/kernel/harvest/harvester/localfilesystem/LocalFilesystemHarvester.java`
- **Function**: `runBeforeScript()`
- **Line Range**: 237-242
- **Description**: The vulnerable code that accepts unsanitized user input and passes it directly to shell execution

### Code Context
```java
private void runBeforeScript() throws IOException, InterruptedException {
    if (StringUtils.isEmpty(params.beforeScript)) {
        return;
    }
    log.info("Running the before script: " + params.beforeScript);
    List<String> args = new ArrayList<String>(Arrays.asList(params.beforeScript.split(" ")));
    Process process = new ProcessBuilder(args).           // LINE 239 - crash_site
            redirectError(ProcessBuilder.Redirect.INHERIT).
            redirectOutput(ProcessBuilder.Redirect.INHERIT).
            start();                                       // LINE 242 - where sanitizer detects injection
    int result = process.waitFor();
    if ( result != 0 ) {
        log.warning("The beforeScript failed with exit value=" + Integer.toString(result));
        throw new RuntimeException("The beforeScript returned an error: " + Integer.toString(result));
    }
}
```

The `params.beforeScript` value comes from XML input parsed in `LocalFilesystemParams.createOrUpdate()`:
```java
beforeScript = Util.getParam(site, "beforeScript", "");
```

This parameter is extracted from the `<beforeScript>` XML element without any validation or sanitization.

## CWE Classification
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-77**: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## Vulnerability Description

This is an **OS Command Injection** vulnerability in GeoNetwork's Local Filesystem Harvester component. An authenticated administrator can execute arbitrary operating system commands on the underlying host through the unsanitized "beforeScript" parameter.

**Root Cause**: The vulnerability exists because the `runBeforeScript()` method accepts user-controlled input from the `params.beforeScript` field (parsed from XML configuration) and passes it directly to `ProcessBuilder` without any validation or sanitization. The input is split by spaces and passed as command-line arguments, allowing an attacker to inject arbitrary shell commands.

**Attack Vector**: An attacker with administrator privileges can create or modify a Local Filesystem Harvester configuration with a malicious `beforeScript` value in the XML input. When the harvester executes, it will run the attacker's arbitrary commands with the privileges of the GeoNetwork application.

**Impact**: This vulnerability allows:
- Remote code execution on the server
- Potential privilege escalation
- Compromise of the underlying host system
- Access to internal network resources
- Data exfiltration or destruction

**Affected Versions**:
- GeoNetwork 3.4.0 through 3.10.6
- GeoNetwork 4.0.0-alpha.1 through 4.0.3

**Patched Versions**:
- GeoNetwork 3.12.0
- GeoNetwork 4.0.4

## POV Analysis

The POV file (`pov_0.blob`) contains a minimal XML payload:
```xml
<node><site><beforeScript>jazze</beforeScript></site></node>
```

This simple payload demonstrates that:
1. The attacker provides an XML configuration with a `beforeScript` element
2. The value "jazze" is parsed and passed to `ProcessBuilder`
3. The system attempts to execute "jazze" as an OS command
4. The Jazzer sanitizer detects this as OS command injection

A real attack could use commands like `/bin/sh -c "malicious_command"` to execute arbitrary code.

## Patch Analysis

The patch (`patch_0.diff`) completely disables the vulnerable functionality:

**Key Changes**:
1. **Line 25**: Throws an `InterruptedException` with message "Script option is currently disabled."
2. **Lines 26-38**: Comments out all the vulnerable code that executed the beforeScript
3. **TODO comment**: Notes that "Script MUST be limited to well known ones added by a catalog admin in the data directory. To be improved"

**Root Cause Location Confirmed**: The patch modifies lines 233-248 of `LocalFilesystemHarvester.java`, specifically the `runBeforeScript()` method. This confirms that the root_cause and crash_site are in the same location - the code that constructs and executes the ProcessBuilder.

**Fix Strategy**: The patch takes a security-first approach by completely disabling the feature rather than attempting to sanitize input. This is appropriate for a critical security vulnerability where proper input validation would be complex. The TODO comment suggests future improvements could include:
- Allowlisting specific scripts
- Restricting script locations to admin-controlled directories
- Implementing proper input validation and sanitization

## Recommendations

**Suggested CWEs**: 
- CWE-78 (Primary - OS Command Injection)
- CWE-94 (Code Injection)
- CWE-77 (Command Injection)

**Vulnerability Name**: "GeoNetwork Local Filesystem Harvester OS Command Injection (CVE-2021-28398)"

**Security Best Practices**:
1. Never pass user-controlled input directly to shell execution functions
2. Use allowlists for permitted commands rather than trying to sanitize input
3. Apply principle of least privilege - restrict what commands can be executed
4. Consider disabling dangerous features that accept arbitrary code execution
5. Implement proper authentication and authorization controls