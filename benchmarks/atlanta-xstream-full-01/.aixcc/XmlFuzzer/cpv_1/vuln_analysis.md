# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: XmlFuzzer
- **Vulnerability Type**: Stack Overflow (Denial of Service)
- **Origin**: 1-day
- **Release Date**: 11/07/2024
- **CVE**: CVE-2024-47072
- **GHSA**: GHSA-hfq9-hggm-c56q
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47072
  - https://github.com/x-stream/xstream/security/advisories/GHSA-hfq9-hggm-c56q
  - https://x-stream.github.io/CVE-2024-47072.html

## Crash Log Analysis
- **Error Type**: Stack Overflow (detected by Jazzer)
- **Crash Location**: xstream/src/java/com/thoughtworks/xstream/io/binary/BinaryStreamReader.java:158
- **Vulnerable Function**: `readToken()`
- **DEDUP Token**: `91afc9fa31866270`
- **Reporter**: Alexis Challande of Trail Of Bits

### Stack Trace
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack overflow (use '-Xss921k' to reproduce)
	at com.thoughtworks.xstream.io.binary.BinaryStreamReader.readToken(BinaryStreamReader.java:158)
Caused by: java.lang.StackOverflowError
	at java.base/sun.nio.cs.CESU_8$Encoder.encodeArrayLoop(CESU_8.java:499)
	at java.base/sun.nio.cs.CESU_8$Encoder.encodeLoop(CESU_8.java:555)
	at java.base/java.nio.charset.CharsetEncoder.encode(CharsetEncoder.java:585)
	at java.base/java.lang.StringCoding.encode(StringCoding.java:487)
	at java.base/java.lang.String.getBytes(String.java:983)
DEDUP_TOKEN: 91afc9fa31866270
```

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause - same location)
- **Type**: crash_site, root_cause
- **File Path**: xstream/src/java/com/thoughtworks/xstream/io/binary/BinaryStreamReader.java
- **Function**: `readToken()`
- **Line Range**: 151-170
- **Vulnerable Line**: 158 (the recursive call)

### Code Context (Vulnerable - Before Patch)
```java
private Token readToken() {
    if (pushback == null) {
        try {
            final Token token = tokenFormatter.read(in);
            switch (token.getType()) {
                case Token.TYPE_MAP_ID_TO_VALUE:
                    idRegistry.put(token.getId(), token.getValue());
                    return readToken(); // Next one please. <-- VULNERABLE: Unbounded recursion
                default:
                    return token;
            }
        } catch (final IOException e) {
            throw new StreamException(e);
        }
    } else {
        Token result = pushback;
        pushback = null;
        return result;
    }
}
```

### Code Context (Fixed - After Patch)
```java
private Token readToken() {
    if (pushback == null) {
        try {
            boolean mapping = false;
            do {
                final Token token = tokenFormatter.read(in);
                switch (token.getType()) {
                    case Token.TYPE_MAP_ID_TO_VALUE:
                        idRegistry.put(token.getId(), token.getValue());
                        mapping ^= true;
                        continue; // Next one please.
                    default:
                        return token;
                }
            } while (mapping);
            throw new InputManipulationException("Binary stream will never have two mapping tokens in sequence");
        } catch (final IOException e) {
            throw new StreamException(e);
        }
    } else {
        Token result = pushback;
        pushback = null;
        return result;
    }
}
```

## CWE Classification
- **CWE-674**: Uncontrolled Recursion
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-1325**: Improperly Controlled Sequential Memory Allocation

## Vulnerability Description

This is a **Denial of Service (DoS) vulnerability via stack overflow** in XStream's `BinaryStreamReader` class, affecting all versions up to and including 1.4.20 when using the BinaryStreamDriver.

### Root Cause
The vulnerability exists in the `readToken()` method at line 158 of `BinaryStreamReader.java`. The method uses **unbounded recursion** to process `TYPE_MAP_ID_TO_VALUE` tokens. When the method encounters a mapping token, it processes it and then recursively calls itself to get the next token:

```java
case Token.TYPE_MAP_ID_TO_VALUE:
    idRegistry.put(token.getId(), token.getValue());
    return readToken(); // Recursive call without bounds checking
```

### Attack Vector
An attacker can craft a malicious binary input stream containing a large sequence of consecutive `TYPE_MAP_ID_TO_VALUE` tokens. Since each mapping token triggers a recursive call, a sufficiently long sequence will exhaust the Java call stack, resulting in a `StackOverflowError`.

The BinaryStreamDriver uses string deduplication with ID mappings during deserialization. The original implementation naively used recursion to skip over mapping tokens and get to the next "normal" token, without considering that an attacker could manipulate the input stream to contain an excessive number of mapping tokens.

### Impact
- **Availability**: Complete denial of service - the application thread terminates with a stack overflow error
- **Confidentiality**: None
- **Integrity**: None
- **CVSS Score**: 7.5 (High)
- **Attack Complexity**: Low - requires only sending a crafted binary stream
- **Privileges Required**: None
- **User Interaction**: None

### Affected Code Location Analysis
Both the **crash_site** and **root_cause** are at the same location (line 158), as this is where both:
1. The program crashes (stack overflow occurs during recursive calls)
2. The defect exists (unbounded recursion without depth checking)

## POV Analysis
The POV file (`pov_0.blob`) is a 36KB binary file that contains a crafted XStream binary format payload with a long sequence of `TYPE_MAP_ID_TO_VALUE` tokens designed to trigger the recursive readToken() calls until the stack is exhausted.

## Patch Analysis

The patch converts the **recursive implementation to an iterative one** with manipulation detection:

### Key Changes:
1. **Eliminates recursion**: Replaces `return readToken()` with a `do-while` loop
2. **Adds manipulation detection**: Uses a boolean `mapping` flag that toggles each time a mapping token is encountered
3. **Throws exception on manipulation**: If two consecutive mapping tokens are detected (mapping flag doesn't alternate correctly), throws `InputManipulationException`

### Fix Logic:
```java
boolean mapping = false;
do {
    final Token token = tokenFormatter.read(in);
    switch (token.getType()) {
        case Token.TYPE_MAP_ID_TO_VALUE:
            idRegistry.put(token.getId(), token.getValue());
            mapping ^= true;  // Toggle flag - should alternate true/false/true/false...
            continue;
        default:
            return token;
    }
} while (mapping);
throw new InputManipulationException("Binary stream will never have two mapping tokens in sequence");
```

The fix ensures that:
- No recursive calls are made (constant stack usage)
- Malicious input with consecutive mapping tokens is detected and rejected
- Legitimate binary streams with alternating mapping and regular tokens work correctly

## Recommendations

### For vuln.yaml generation:
- **CWEs**: [CWE-674, CWE-400, CWE-1325]
- **Vulnerability name**: "Stack Overflow in XStream BinaryStreamReader via Recursive Token Processing"
- **Origin**: 1-day
- **Release date**: 11/07/2024
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47072
  - https://github.com/x-stream/xstream/security/advisories/GHSA-hfq9-hggm-c56q
- **Location type**: Both crash_site and root_cause at same location
- **File**: xstream/src/java/com/thoughtworks/xstream/io/binary/BinaryStreamReader.java
- **Function**: readToken
- **Line**: 158 (vulnerable recursive call)
- **Line range**: 151-170 (entire method)