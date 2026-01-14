# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: StrutsOne
- **Vulnerability Type**: Expression Language Injection leading to Remote Code Execution
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
- **Crash Location**: Multiple locations in stack trace, with evaluation happening in ELAttributeEvaluator.evaluate
- **Vulnerable Function**: org.apache.tiles.api.Attribute.setValue (root cause)
- **DEDUP Token**: 4d94b040a0a5ac46

### Stack Trace
The crash log shows the following critical stack trace:
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh: Remote Code Execution
Unrestricted class/object creation based on externally controlled data may allow
remote code execution depending on available classes on the classpath.
        at jaz.Zer.reportFinding(Zer.java:110)
        at jaz.Zer.el(Zer.java:99)
        ...
        at jakarta.el.BeanELResolver.invoke(BeanELResolver.java:462)
        at jakarta.el.CompositeELResolver.invoke(CompositeELResolver.java:195)
        at com.sun.el.parser.AstValue.getValue(AstValue.java:110)
        at com.sun.el.parser.AstValue.getValue(AstValue.java:177)
        at com.sun.el.ValueExpressionImpl.getValue(ValueExpressionImpl.java:183)
        at org.apache.tiles.el.ELAttributeEvaluator.evaluate(ELAttributeEvaluator.java:90)
        at org.apache.tiles.core.evaluator.AbstractAttributeEvaluator.evaluate(AbstractAttributeEvaluator.java:44)
        at com.aixcc.struts.harnesses.one.StrutsOne$CalculateAction.execute(StrutsOne.java:115)
```

## Vulnerable Code Location(s)

### Location 1 (root_cause)
- **Type**: root_cause
- **File Path**: plugins/tiles/src/main/java/org/apache/tiles/api/Attribute.java
- **Function**: setValue
- **Line Range**: 235-244
- **Column Range**: 1-6

### Location 2 (crash_site)
- **Type**: crash_site
- **File Path**: plugins/tiles/src/main/java/org/apache/tiles/el/ELAttributeEvaluator.java
- **Function**: evaluate
- **Line Range**: 82-91
- **Column Range**: 1-6

### Code Context - Root Cause

The vulnerable code in `Attribute.java` (lines 235-244):
```java
public void setValue(Object value) {
    this.value = value;
    if (value instanceof String) {
        // Use expressions for string values to simplify and use a common
        // code path.
        String stringVal = ((String) value);
        this.expressionObject = new Expression(stringVal.replace("${", "\\${"));
        this.value = null;
    }
}
```

**The Problem**: The `setValue` method automatically converts any string value into an Expression Language expression by attempting to escape `${` with `\\${`. However, this escaping is insufficient and can be bypassed. The method unconditionally treats string inputs as potential EL expressions, enabling injection attacks.

### Code Context - Crash Site

The crash occurs in `ELAttributeEvaluator.java` (lines 82-91):
```java
public Object evaluate(String expression, Request request) {
    ELContextImpl context = new ELContextImpl(resolver);
    context.putContext(Request.class, request);
    context.putContext(ApplicationContext.class,
            request.getApplicationContext());
    ValueExpression valueExpression = expressionFactory
            .createValueExpression(context, expression, Object.class);

    return valueExpression.getValue(context);
}
```

**The Issue**: The `evaluate` method directly evaluates the expression without proper validation or sanitization of the expression string that was manipulated in `Attribute.setValue`.

## CWE Classification
- **CWE-917**: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')

## Vulnerability Description

This vulnerability allows remote code execution through Expression Language (EL) injection in Apache Tiles framework. The root cause is in the `Attribute.setValue()` method, which automatically converts string values into EL expressions.

**Attack Flow**:
1. Attacker provides malicious input containing EL expressions (e.g., `#{Byte.class.forName("jaz.Zer").getMethod("el").invoke(null)}`)
2. The `setValue()` method processes the string and creates an Expression object
3. The expression is later evaluated by `ELAttributeEvaluator.evaluate()`
4. The EL evaluation engine executes the malicious code with full application context access
5. Attacker achieves remote code execution

**Key Vulnerability Characteristics**:
- The `setValue` method's automatic conversion of strings to expressions creates an unsafe default behavior
- The insufficient escaping mechanism (`replace("${", "\\${")`) can be bypassed using alternative EL syntaxes like `#{...}`
- No validation or sanitization of expression content before evaluation
- The Expression object is evaluated with full application context, allowing unrestricted class/method access

**Impact**:
- Remote Code Execution (RCE)
- Unrestricted access to server-side classes and methods
- Potential data exfiltration
- Complete system compromise

## POV Analysis

The proof-of-vulnerability file (`pov_0.blob`) contains:
```
operand\ 1\ result\ 2\ name\ #{Byte.class.forName("jaz.Zer").getMethod("el").invoke(null)}\ 
```

**Analysis**:
- The POV uses the alternative EL syntax `#{...}` instead of `${...}` to bypass the escaping in `setValue`
- The expression `Byte.class.forName("jaz.Zer").getMethod("el").invoke(null)` demonstrates arbitrary code execution
- It invokes a method from the Jazzer fuzzing framework's security checker (`jaz.Zer.el`), which triggers the security issue detection
- This demonstrates that an attacker can:
  - Load arbitrary classes via reflection (`forName`)
  - Invoke arbitrary methods (`getMethod`, `invoke`)
  - Execute code in the security context of the application

## Patch Analysis

The patch (`patch_0.diff`) removes the problematic automatic expression conversion:

**Changes in `Attribute.java`**:
```diff
 public void setValue(Object value) {
     this.value = value;
-    if (value instanceof String) {
-        // Use expressions for string values to simplify and use a common
-        // code path.
-        String stringVal = ((String) value);
-        this.expressionObject = new Expression(stringVal.replace("${", "\\${"));
-        this.value = null;
-    }
 }
```

**Fix Analysis**:
- The patch completely removes the automatic conversion of string values to Expression objects
- This prevents untrusted input from being automatically treated as EL expressions
- String values are now stored as-is in the `value` field without creating an `expressionObject`
- This is a defense-in-depth approach: if expressions need to be evaluated, they must be explicitly set via `setExpressionObject()` method, not automatically inferred from string content

**Security Improvement**:
- Separates data (string values) from code (expressions)
- Requires explicit intent to use expressions
- Prevents injection attacks through implicit expression conversion
- Eliminates the unsafe default behavior

## Recommendations
- **Suggested CWEs**: CWE-917, CWE-94
- **Vulnerability Name**: Expression Language Injection in Apache Tiles Attribute.setValue
- **Severity**: Critical (Remote Code Execution)
- **Classification**: synthetic (no exact CVE match found)