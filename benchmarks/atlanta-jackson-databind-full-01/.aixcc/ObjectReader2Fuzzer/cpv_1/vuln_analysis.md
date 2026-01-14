# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: ObjectReader2Fuzzer
- **Vulnerability Type**: Stack overflow (Resource exhaustion via deep recursion)
- **Origin**: 1-day
- **Release Date**: 10/02/2022
- **CVE**: CVE-2022-42003
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2022-42003
  - https://github.com/FasterXML/jackson-databind/issues/3590
  - https://github.com/advisories/GHSA-jjjh-jjxp-wpff
  - https://osv.dev/vulnerability/CVE-2022-42003

## Crash Log Analysis
- **Error Type**: Stack overflow (FuzzerSecurityIssueLow)
- **Crash Location**: StdDeserializer.java:416
- **Vulnerable Function**: `_parseBooleanPrimitive`
- **Error Message**: `com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow`

### Stack Trace
The crash log shows a recursive call pattern in `_parseBooleanPrimitive`:

```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)
	at com.fasterxml.jackson.databind.deser.std.StdDeserializer._parseBooleanPrimitive(StdDeserializer.java:416)
	at com.fasterxml.jackson.core.json.JsonReadContext.createChildArrayContext(JsonReadContext.java:157)
	at com.fasterxml.jackson.core.base.ParserBase.createChildArrayContext(ParserBase.java:1360)
	at com.fasterxml.jackson.core.json.UTF8StreamJsonParser._nextTokenNotInObject(UTF8StreamJsonParser.java:832)
	at com.fasterxml.jackson.core.json.UTF8StreamJsonParser.nextToken(UTF8StreamJsonParser.java:753)
	at com.fasterxml.jackson.databind.deser.std.StdDeserializer._parseBooleanPrimitive(StdDeserializer.java:415)
	at com.fasterxml.jackson.databind.deser.std.StdDeserializer._parseBooleanPrimitive(StdDeserializer.java:416)
	[... repeated many times ...]
```

The stack trace shows the function calling itself recursively at line 416, triggered by line 415 (`p.nextToken()`).

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/main/java/com/fasterxml/jackson/databind/deser/std/StdDeserializer.java
- **Function**: `_parseBooleanPrimitive`
- **Line Range**: 416-416
- **Column Range**: 1-52

### Location 2 (root_cause) 
- **Type**: root_cause
- **File Path**: src/main/java/com/fasterxml/jackson/databind/deser/std/StdDeserializer.java
- **Function**: `_parseBooleanPrimitive`
- **Line Range**: 414-419
- **Column Range**: 1-20

### Code Context

**Vulnerable code (before patch):**
```java
case JsonTokenId.ID_START_ARRAY:
    // 12-Jun-2020, tatu: For some reason calling `_deserializeFromArray()` won't work so
    if (ctxt.isEnabled(DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS)) {
        p.nextToken();                                      // Line 415
        final boolean parsed = _parseBooleanPrimitive(p, ctxt);  // Line 416 - RECURSIVE CALL
        _verifyEndArrayForSingle(p, ctxt);
        return parsed;
    }
    // fall through
```

The vulnerability is on line 416 where `_parseBooleanPrimitive` recursively calls itself without any depth check. When processing deeply nested arrays (e.g., `[[[[[...`), each nested array triggers another recursive call, eventually exhausting the stack.

## CWE Classification
- **CWE-674**: Uncontrolled Recursion
- **CWE-400**: Uncontrolled Resource Consumption

## Vulnerability Description

This vulnerability exists in the Jackson-databind library's `StdDeserializer._parseBooleanPrimitive()` method. When the `UNWRAP_SINGLE_VALUE_ARRAYS` deserialization feature is enabled, the method recursively unwraps nested arrays without any depth limitation.

**Root Cause**: The method handles `START_ARRAY` tokens by calling `p.nextToken()` and then recursively calling itself to parse the inner content. This recursive pattern lacks any depth checking mechanism, allowing an attacker to craft deeply nested array inputs that exhaust the call stack.

**Attack Vector**: An attacker can provide a maliciously crafted JSON input with excessive array nesting (e.g., `{"_boolean": [[[[[...true...]]]]]}`). When parsed with `UNWRAP_SINGLE_VALUE_ARRAYS` enabled, each nested array level triggers another recursive call, leading to stack overflow and denial of service.

**Impact**: 
- **Severity**: High (CVSS 7.5)
- **Type**: Denial of Service (DoS) through resource exhaustion
- **Condition**: Only exploitable when the non-default `UNWRAP_SINGLE_VALUE_ARRAYS` feature is enabled
- **Effect**: Application crash due to stack overflow, causing service unavailability

**Affected Versions**:
- jackson-databind 2.4.0-rc1 through 2.12.7.0
- jackson-databind 2.13.0 through 2.13.4.1

**Fixed Versions**:
- 2.12.7.1
- 2.13.4.2
- 2.14.0

## POV Analysis

The POV file (`pov_0.blob`) contains a deeply nested array structure:

```json
{ "_boolean":[[[[[[[[[[[[[[[[[[[[[[[[[...
```

The payload consists of:
1. A JSON object with a `_boolean` field
2. Hundreds of opening square brackets `[` creating deeply nested arrays
3. This structure is specifically designed to trigger the recursive behavior in `_parseBooleanPrimitive`

When the ObjectReader2Fuzzer processes this input with `UNWRAP_SINGLE_VALUE_ARRAYS` enabled, each nested array level causes another recursive call to `_parseBooleanPrimitive`, eventually exhausting the Java Virtual Machine's stack space (default ~1MB), resulting in a `StackOverflowError`.

## Patch Analysis

The patch adds a check for nested arrays before making the recursive call:

```diff
case JsonTokenId.ID_START_ARRAY:
    // 12-Jun-2020, tatu: For some reason calling `_deserializeFromArray()` won't work so
    if (ctxt.isEnabled(DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS)) {
-        p.nextToken();
-        final boolean parsed = _parseBooleanPrimitive(p, ctxt);
+        if (p.nextToken() == JsonToken.START_ARRAY) {
+            return (boolean) handleNestedArrayForSingle(p, ctxt);
+        }
+        final boolean parsed = _parseBooleanPrimitive(p, ctxt);
        _verifyEndArrayForSingle(p, ctxt);
        return parsed;
    }
```

**Key Changes**:
1. **Nested array detection**: After calling `p.nextToken()`, the patch checks if the next token is another `START_ARRAY`
2. **Special handling**: If a nested array is detected, it delegates to `handleNestedArrayForSingle()` instead of recursively calling `_parseBooleanPrimitive()`
3. **Breaking recursion**: This prevents the unbounded recursion that caused the stack overflow

The fix effectively limits the depth of array unwrapping by detecting when nested arrays occur and handling them through a different code path (`handleNestedArrayForSingle`), which presumably includes proper depth checks or iterative processing to avoid stack exhaustion.

## Recommendations

- **Origin Classification**: `1-day` (confirmed real-world vulnerability with CVE)
- **CVE**: CVE-2022-42003
- **Suggested CWEs**: [CWE-674, CWE-400]
- **Vulnerability Name**: Deep Wrapper Array Nesting in Primitive Deserializers
- **Release Date**: 10/02/2022 (NVD published date)

---

## Additional Context

This vulnerability was discovered through OSS-Fuzz fuzzing and reported in GitHub issue #3590. It's part of a broader class of vulnerabilities (along with CVE-2022-42004) affecting multiple primitive deserializer methods in jackson-databind:
- `_parseBooleanPrimitive()`
- `_parseBytePrimitive()`
- `_parseShortPrimitive()`
- `_parseIntPrimitive()`
- `_parseLongPrimitive()`
- `_parseFloatPrimitive()`
- `_parseDoublePrimitive()`

The vulnerability only affects configurations where the non-default `UNWRAP_SINGLE_VALUE_ARRAYS` feature is explicitly enabled, limiting its attack surface in practice.