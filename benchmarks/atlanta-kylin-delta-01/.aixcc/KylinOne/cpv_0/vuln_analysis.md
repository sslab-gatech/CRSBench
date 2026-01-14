# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: KylinOne
- **Vulnerability Type**: OS Command Injection
- **Origin**: 1-day
- **Release Date**: 05/22/2020
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2020-1956
  - https://www.openwall.com/lists/oss-security/2020/05/20/1
  - https://kylin.apache.org/docs/4.0.4/security/

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: OS Command Injection
- **Crash Location**: org.apache.kylin.common.util.CliCommandExecutor.runNativeCommand (line 126)
- **Vulnerable Functions**: 
  - `org.apache.kylin.rest.service.CubeService.migrateCube()` (line 884)
  - `org.apache.kylin.rest.controller.CubeController.migrateCube()` (line 1037)
- **DEDUP Token**: ffe44f58ff9f52cd

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.java:63)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
	at org.apache.kylin.common.util.CliCommandExecutor.runNativeCommand(CliCommandExecutor.java:126)
	at org.apache.kylin.common.util.CliCommandExecutor.execute(CliCommandExecutor.java:86)
	at org.apache.kylin.rest.service.CubeService.migrateCube(CubeService.java:884)
	at org.apache.kylin.rest.controller.CubeController.migrateCube(CubeController.java:1037)
	at com.aixcc.kylin.harnesses.one.KylinOne.fuzz(KylinOne.java:105)
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: core-common/src/main/java/org/apache/kylin/common/util/CliCommandExecutor.java
- **Function**: runNativeCommand
- **Line Range**: 124-126
- **Column Range**: N/A (Java - columns not tracked)

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: server-base/src/main/java/org/apache/kylin/rest/service/CubeService.java
- **Function**: migrateCube
- **Line Range**: 874-876
- **Column Range**: N/A (Java - columns not tracked)

### Code Context

**Crash Site (CliCommandExecutor.java:124-126):**
```java
ProcessBuilder builder = new ProcessBuilder(cmd.split(" "));
builder.redirectErrorStream(true);
Process proc = builder.start();  // Line 126 - where command execution occurs
```

**Root Cause (CubeService.java:874-876):**
```java
String stringBuilder = ("%s/bin/kylin.sh org.apache.kylin.tool.CubeMigrationCLI %s %s %s %s %s %s true true");
String cmd = String.format(stringBuilder, KylinConfig.getKylinHome(), srcCfgUri, dstCfgUri, cube.getName(),
        projectName, config.isAutoMigrateCubeCopyAcl(), config.isAutoMigrateCubePurge());
```

The vulnerability occurs because user-controlled parameters (`cube.getName()` and `projectName`) are directly concatenated into an OS command string without sanitization or validation. These parameters come from the REST API endpoint `/kylin/api/cubes/{cube}/{project}/migrate`.

## CWE Classification
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-77**: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## Vulnerability Description

This is **CVE-2020-1956**, a critical OS command injection vulnerability in Apache Kylin's cube migration feature. The vulnerability exists in the `migrateCube()` method of `CubeService` class, which is exposed via a REST API endpoint at `/kylin/api/cubes/{cube}/{project}/migrate`.

### Technical Details

The vulnerable code constructs an OS command by concatenating user-supplied parameters (`cube` name and `project` name) directly into a shell command string without any validation or sanitization:

```java
String cmd = String.format(stringBuilder, KylinConfig.getKylinHome(), srcCfgUri, dstCfgUri, 
    cube.getName(), projectName, config.isAutoMigrateCubeCopyAcl(), config.isAutoMigrateCubePurge());
```

An attacker can inject shell metacharacters (particularly backticks `` ` ``) into the `cube` or `project` parameters to execute arbitrary OS commands. The command is then executed via `ProcessBuilder` without any protection.

### Attack Vector

The POV file demonstrates the attack by injecting backticks in the project name:
```
kylin_streaming_cube `jazze`
```

This would result in executing the `jazze` command on the server. A more dangerous example from the CVE disclosure:
```
http://target/kylin/api/cubes/kylin_streaming_cube/`sleep+10`/migrate
```

### Impact

- **Severity**: HIGH (CVSS 8.8)
- Remote Code Execution (RCE) capability
- Complete system compromise possible
- Listed in CISA's Known Exploited Vulnerabilities Catalog

### Affected Versions
- Kylin 2.3.0 to 2.3.2
- Kylin 2.4.0 to 2.4.1
- Kylin 2.5.0 to 2.5.2
- Kylin 2.6.0 to 2.6.5
- Kylin 3.0.0-alpha through 3.0.1

### Discovery
Discovered by Johannes Dahse and disclosed on May 22, 2020.

## POV Analysis

The POV file (`pov_0.blob`) contains:
```
      !   kylin_streaming_cube `
jazze
`
```

This demonstrates command injection through the project/cube name parameter. The backticks (`` ` ``) are shell command substitution operators that allow executing arbitrary commands. The fuzzer (Jazzer) successfully detected this as an OS command injection vulnerability with its built-in security sanitizers.

## Patch Analysis

The patch introduces two security measures:

### 1. Input Validation Helper Methods (CliCommandExecutor.java)

Added three new methods for parameter validation:
- `checkParameter(String commandParameter)`: Uses blacklist regex to remove dangerous characters
- `checkParameterWhiteList(String commandParameter)`: Uses whitelist regex to only allow safe characters
- Private `checkParameter(String commandParameter, String rex)`: Core validation logic

**Blacklist regex** (`COMMAND_INJECT_REX`):
```java
"[ &`>|{}()$;\\-#~!+*"\\\\]+"
```
Blocks common shell metacharacters including backticks, pipes, semicolons, etc.

**Whitelist regex** (`COMMAND_WHITE_LIST`):
```java
"[^\\w%,@/:=?.\"\\[\\]]"
```
Only allows word characters, percent signs, commas, at-signs, slashes, colons, equals, question marks, dots, quotes, and brackets (safe for URI/path expressions).

### 2. Sanitization at Call Site (CubeService.java:874-876)

Modified the command construction to sanitize user-controlled parameters:
```java
String cmd = String.format(Locale.ROOT,
    stringBuilder,
    KylinConfig.getKylinHome(),
    CliCommandExecutor.checkParameterWhiteList(srcCfgUri),    // Sanitized
    CliCommandExecutor.checkParameterWhiteList(dstCfgUri),    // Sanitized
    cube.getName(),
    CliCommandExecutor.checkParameterWhiteList(projectName),  // Sanitized
    config.isAutoMigrateCubeCopyAcl(),
    config.isAutoMigrateCubePurge());
```

The patch applies `checkParameterWhiteList()` to all user-controlled parameters (`srcCfgUri`, `dstCfgUri`, and `projectName`) before concatenating them into the shell command. This removes any dangerous characters and prevents command injection.

## Recommendations
- **Suggested CWEs**: [CWE-78, CWE-77]
- **Vulnerability Name**: OS Command Injection in Apache Kylin Cube Migration API (CVE-2020-1956)
- **Origin Classification**: 1-day (confirmed CVE with official disclosure)
- **Release Date**: 05/22/2020