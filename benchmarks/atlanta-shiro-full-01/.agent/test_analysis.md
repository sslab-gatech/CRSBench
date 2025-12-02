# Test Analysis for Apache Shiro (atlanta-shiro-full-01)

**Project:** Apache Shiro Security Framework
**Base Commit:** ea2d77a3f30108802236138a2e3abfd3ea8ec59a
**Repository:** `/home/acorn421/work/team-atlanta/afc-repos/cp-java-shiro-src-ea2d77a3`
**Analysis Date:** 2024-11-22

## Executive Summary

This document provides a comprehensive analysis of all test files in the Apache Shiro project for use in patch generation and CRS evaluation. The project contains **142 test files** (109 Java + 33 Groovy) organized across multiple Maven modules with JUnit 4.8.2 as the primary testing framework.

## 1. Build System and Test Framework

### Build System
- **Type:** Apache Maven (Multi-module project)
- **Maven Surefire Plugin:** Version 2.12
- **Java Version:** JDK 1.6
- **Build Configuration:** Root `pom.xml` with multi-module structure

### Test Framework
- **Primary Framework:** JUnit 4.8.2
- **Secondary Framework:** Groovy tests via GMaven Plugin 1.3
- **Mocking Framework:** EasyMock 3.1
- **Test Execution:** Maven Surefire Plugin with `printSummary=true`

### Maven Modules with Tests
1. `core/` - Core security functionality (70 Java + 33 Groovy tests)
2. `web/` - Web integration (16 Java tests)
3. `support/aspectj/` - AspectJ support (4 Java tests)
4. `support/ehcache/` - EhCache integration (1 Java test)
5. `support/guice/` - Google Guice integration (21 Java tests)
6. `support/spring/` - Spring Framework integration (8 Java tests)
7. `samples/aspectj/` - AspectJ sample (1 Java test)
8. `samples/web/` - Web sample (2 Java tests)

## 2. Test File Inventory

### 2.1 Core Module Tests (core/src/test/)

#### Java Test Files (70 files)

**Authentication Tests:**
- `authc/AbstractAuthenticatorTest.java`
- `authc/SimpleAuthenticationInfoTest.java`
- `authc/ConcurrentAccessExceptionTest.java`
- `authc/ExcessiveAttemptsExceptionTest.java`
- `authc/ExpiredCredentialsExceptionTest.java`
- `authc/IncorrectCredentialsExceptionTest.java`
- `authc/LockedAccountExceptionTest.java`
- `authc/UnknownAccountExceptionTest.java`

**Credential Matcher Tests:**
- `authc/credential/AbstractHashedCredentialsMatcherTest.java`
- `authc/credential/AllowAllCredentialsMatcherTest.java`
- `authc/credential/HashedCredentialsMatcherTest.java`
- `authc/credential/Md2CredentialsMatcherTest.java`
- `authc/credential/Md5CredentialsMatcherTest.java`
- `authc/credential/Sha1CredentialsMatcherTest.java`
- `authc/credential/Sha256CredentialsMatcherTest.java`
- `authc/credential/Sha384CredentialsMatcherTest.java`
- `authc/credential/Sha512CredentialsMatcherTest.java`

**Authentication Strategy Tests:**
- `authc/pam/AllSuccessfulStrategyTest.java`

**Authorization Tests:**
- `authz/AuthorizationExceptionTest.java`
- `authz/HostUnauthorizedExceptionTest.java`
- `authz/ModularRealmAuthorizerTest.java`
- `authz/UnauthenticatedExceptionTest.java`
- `authz/UnauthorizedExceptionTest.java`
- `authz/aop/PermissionAnnotationHandlerTest.java`
- `authz/aop/RoleAnnotationHandlerTest.java`

**Permission Tests:**
- `authz/permission/AllPermissionTest.java`
- `authz/permission/DomainPermissionTest.java`
- `authz/permission/WildcardPermissionTest.java`

**Security Manager Tests:**
- `mgt/AbstractRememberMeManagerTest.java`
- `mgt/AbstractSecurityManagerTest.java`
- `mgt/DefaultSecurityManagerTest.java`
- `mgt/VMSingletonDefaultSecurityManagerTest.java`

**Realm Tests:**
- `realm/AuthorizingRealmTest.java`
- `realm/activedirectory/ActiveDirectoryRealmTest.java`
- `realm/jdbc/JDBCRealmTest.java`
- `realm/ldap/DefaultLdapContextFactoryTest.java`
- `realm/ldap/JndiLdapContextFactoryTest.java`
- `realm/ldap/JndiLdapRealmTest.java`
- `realm/text/IniRealmTest.java`
- `realm/text/TextConfigurationRealmTest.java`

**Session Management Tests:**
- `session/mgt/AbstractValidatingSessionManagerTest.java`
- `session/mgt/DefaultSessionManagerTest.java`
- `session/mgt/DelegatingSessionTest.java`
- `session/mgt/SimpleSessionTest.java`

**Subject Tests:**
- `subject/DelegatingSubjectTest.java`

**Configuration Tests:**
- `config/IniTest.java`
- `config/CompositeBean.java` (test helper)
- `config/HashMapCacheManager.java` (test helper)
- `config/InitializableBean.java` (test helper)
- `config/SimpleBeanFactory.java` (test helper)
- `config/SimpleBean.java` (test helper)

**Cryptography Tests:**
- `crypto/AesCipherServiceTest.java`
- `crypto/BlowfishCipherServiceTest.java`
- `crypto/JcaCipherServiceTest.java`
- `crypto/SecureRandomNumberGeneratorTest.java`

**Concurrent Tests:**
- `concurrent/SubjectAwareExecutorServiceTest.java`
- `concurrent/SubjectAwareExecutorTest.java`

**AOP Tests:**
- `aop/AnnotationResolverTest.java`

**Utility Tests:**
- `util/RegExPatternMatcherTest.java`
- `util/StringUtilsTest.java`

**Other Tests:**
- `ExceptionTest.java`
- `io/SerializationExceptionTest.java`
- `jndi/JndiObjectFactoryTest.java`
- `test/AbstractShiroTest.java` (base test class)
- `test/ExampleShiroIntegrationTest.java` (example)
- `test/ExampleShiroUnitTest.java` (example)
- `test/SecurityManagerTestSupport.java` (test helper)
- `AtUnitTestBase.java` (base test class)
- `realm/UserIdPrincipal.java` (test helper)
- `realm/UsernamePrincipal.java` (test helper)

#### Groovy Test Files (33 files)

**Configuration Tests:**
- `config/IniSecurityManagerFactoryTest.groovy`
- `config/MockPermissionResolver.groovy`
- `config/ReflectionBuilderTest.groovy`

**Authentication Tests:**
- `authc/credential/DefaultPasswordServiceTest.groovy`
- `authc/credential/PasswordMatcherTest.groovy`
- `authc/pam/ModularRealmAuthenticatorTest.groovy`

**Realm Tests:**
- `realm/AuthenticatingRealmTest.groovy`
- `realm/AuthenticatingRealmIntegrationTest.groovy`
- `realm/TestAuthenticatingRealm.groovy`
- `realm/CachingRealmTest.groovy`

**Cryptography Tests:**
- `codec/H64Test.groovy`
- `crypto/hash/HashRequestBuilderTest.groovy`
- `crypto/hash/DefaultHashServiceTest.groovy`
- `crypto/hash/format/Base64FormatTest.groovy`
- `crypto/hash/format/DefaultHashFormatFactoryTest.groovy`
- `crypto/hash/format/HexFormatTest.groovy`
- `crypto/hash/format/ProvidedHashFormatTest.groovy`
- `crypto/hash/format/Shiro1CryptFormatTest.groovy`
- `crypto/hash/format/ToStringHashFormat.groovy` (test helper)

**Subject DAO Tests:**
- `mgt/DefaultSubjectDAOTest.groovy`

**Additional Groovy Tests:** (13 more files found in core/src/test/groovy/)

### 2.2 Web Module Tests (web/src/test/)

**16 Java Test Files:**
- `config/WebIniSecurityManagerFactoryTest.java`
- `filter/authc/AnonymousFilterTest.java`
- `filter/authc/BasicHttpFilterAuthenticationTest.java`
- `filter/authz/AuthorizationFilterTest.java`
- `filter/authz/HostFilterTest.java`
- `filter/authz/HttpMethodPermissionFilterTest.java`
- `filter/authz/PortFilterTest.java`
- `filter/mgt/PathMatchingFilterChainResolverTest.java`
- `filter/mgt/SimpleNamedFilterListTest.java`
- `filter/PathMatchingFilterTest.java`
- `mgt/AbstractWebSecurityManagerTest.java`
- `mgt/CookieRememberMeManagerTest.java`
- `mgt/DefaultWebSecurityManagerTest.java`
- `servlet/OncePerRequestFilterTest.java`
- `servlet/SimpleCookieTest.java`
- `WebTest.java`

### 2.3 Support Module Tests

#### AspectJ Support (support/aspectj/src/test/)
**4 Java Test Files:**
- `aspectj/DummyService.java` (test helper)
- `aspectj/DummyServiceTest.java`
- `aspectj/RestrictedDummyService.java` (test helper)
- `aspectj/SecuredDummyService.java` (test helper)

#### EhCache Support (support/ehcache/src/test/)
**1 Java Test File:**
- `cache/ehcache/EhCacheManagerTest.java`

#### Guice Support (support/guice/src/test/)
**21 Java Test Files:**
- `guice/aop/AopAllianceMethodInterceptorAdapterTest.java`
- `guice/aop/AopAllianceMethodInvocationAdapterTest.java`
- `guice/aop/ShiroAopModuleTest.java`
- `guice/BeanTypeListenerTest.java`
- `guice/DestroyableInjectionListenerTest.java`
- `guice/GuiceEnvironmentTest.java`
- `guice/InitializableInjectionListenerTest.java`
- `guice/LifecycleTypeListenerTest.java`
- `guice/ShiroMatchersTest.java`
- `guice/ShiroModuleTest.java`
- `guice/ShiroSessionScopeTest.java`
- `guice/web/AbstractInjectionProviderTest.java`
- `guice/web/DefaultFiltersTest.java`
- `guice/web/FilterChainResolverProviderTest.java`
- `guice/web/FilterConfigTest.java`
- `guice/web/GuiceShiroFilterTest.java`
- `guice/web/PathMatchingFilterProviderTest.java`
- `guice/web/ShiroWebModuleTest.java`
- `guice/web/SimpleFilterChainResolverTest.java`
- `guice/web/SimpleFilterChainTest.java`
- `guice/web/WebGuiceEnvironmentTest.java`

#### Spring Support (support/spring/src/test/)
**8 Java Test Files:**
- `spring/remoting/SecureRemoteInvocationFactoryTest.java`
- `spring/security/interceptor/AbstractAuthorizationAnnotationTest.java`
- `spring/security/interceptor/DapcAuthorizationAnnotationTest.java`
- `spring/security/interceptor/DefaultTestService.java` (test helper)
- `spring/security/interceptor/SchemaAuthorizationAnnotationTest.java`
- `spring/security/interceptor/TestService.java` (test helper)
- `spring/web/DummyFilter.java` (test helper)
- `spring/web/ShiroFilterFactoryBeanTest.java`

### 2.4 Sample Module Tests

#### AspectJ Sample (samples/aspectj/src/test/)
**1 Java Test File:**
- `samples/aspectj/bank/SecureBankServiceTest.java`

#### Web Sample (samples/web/src/test/)
**2 Java Test Files:**
- `test/AbstractContainerTest.java` (base test class)
- `test/ContainerIntegrationTest.java`

### 2.5 Test Resources

Test resource directories exist in:
- `core/src/test/resources/`
- `web/src/test/resources/`
- `samples/aspectj/src/test/resources/`
- `support/aspectj/src/test/resources/`
- `support/ehcache/src/test/resources/`
- `support/spring/src/test/resources/`

## 3. Test Commands

### Run All Tests
```bash
mvn clean test
```

### Run Tests for Specific Module
```bash
mvn clean test -pl core
mvn clean test -pl web
mvn clean test -pl support/spring
mvn clean test -pl support/guice
```

### Run Single Test Class
```bash
mvn test -Dtest=DefaultSecurityManagerTest
mvn test -Dtest=WildcardPermissionTest
```

### Skip Tests During Build
```bash
mvn clean install -DskipTests
```

### Run with Coverage (if configured)
```bash
mvn clean test jacoco:report
```

## 4. Test File Patterns

### Naming Conventions
- **Unit Tests:** `*Test.java`, `*Test.groovy`
- **Integration Tests:** `*IntegrationTest.java`, `*IntegrationTest.groovy`
- **Test Helpers:** Classes in test directories without `Test` suffix
- **Base Classes:** `Abstract*Test.java`, `*TestSupport.java`, `*TestBase.java`

### Directory Structure
```
<module>/
├── src/
│   ├── main/
│   │   └── java/org/apache/shiro/...
│   └── test/
│       ├── java/org/apache/shiro/...  (Java tests)
│       ├── groovy/org/apache/shiro/... (Groovy tests, core only)
│       └── resources/                  (Test resources)
```

## 5. Comprehensive Patch Exclude List

### Java-Specific Test Exclusions

```yaml
patch_exclude_list:
  # Build and configuration files
  - build.sh
  - Dockerfile
  - pom.xml
  - '**/pom.xml'
  - .gitignore
  - .aixcc/**
  - .oss-fuzz/**

  # Documentation
  - '*.md'
  - README*
  - docs/**
  - LICENSE
  - NOTICE

  # Test directories (Maven standard)
  - '**/src/test/**'
  - test/**
  - tests/**

  # Test files by naming convention
  - '**/*Test.java'
  - '**/*Test.groovy'
  - '**/*Tests.java'
  - '**/*Tests.groovy'
  - '**/Test*.java'
  - '**/Test*.groovy'
  - '**/*TestCase.java'
  - '**/*IntegrationTest.java'
  - '**/*IntegrationTest.groovy'

  # Test helper and support classes
  - '**/*TestSupport.java'
  - '**/*TestBase.java'
  - '**/AbstractTest*.java'
  - '**/Abstract*Test.java'
  - '**/*TestHelper.java'
  - '**/*TestUtils.java'
  - '**/test/*.java'
  - '**/test/*.groovy'

  # Compiled test artifacts
  - '**/target/test-classes/**'
  - '**/target/surefire-reports/**'

  # Sample applications (not production code)
  - samples/**

  # Fuzzing harness (OSS-Fuzz specific)
  - fuzz/**
  - '**/fuzz/**'

  # Maven build artifacts
  - target/**
  - '**/target/**'

  # IDE and build artifacts
  - .idea/**
  - .vscode/**
  - '*.iml'
  - .classpath
  - .project
  - .settings/**
```

### Alternative Glob-Based Exclusions

For tools that prefer glob patterns over YAML lists:

```
# Test sources
**/src/test/**
test/**
tests/**

# Test files
**/*Test.java
**/*Test.groovy
**/*Tests.java
**/*TestCase.java
**/*IntegrationTest.java
**/Test*.java
**/Abstract*Test.java

# Build artifacts
**/target/**
**/build/**

# Samples and fuzzing
samples/**
fuzz/**

# Configuration
**/pom.xml
build.sh
Dockerfile
```

## 6. Test Execution Analysis

### Surefire Configuration
From root `pom.xml`:
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>2.12</version>
    <configuration>
        <printSummary>true</printSummary>
    </configuration>
</plugin>
```

### GMaven Plugin for Groovy Tests
```xml
<plugin>
    <groupId>org.codehaus.gmaven</groupId>
    <artifactId>gmaven-plugin</artifactId>
    <version>1.3</version>
    <executions>
        <execution>
            <goals>
                <goal>compile</goal>
                <goal>testCompile</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

### Dependencies
- **JUnit:** 4.8.2 (test scope)
- **EasyMock:** 3.1 (test scope)
- **Groovy:** 1.8.5 (for Groovy tests)

## 7. Recommendations for CRS Patch Generation

### Files to ALWAYS Exclude
1. **All files under `src/test/` directories** - These are pure test code
2. **Sample applications** - Not production code
3. **Fuzzing harnesses** - OSS-Fuzz specific test code
4. **Build configuration** - pom.xml, build.sh, Dockerfile
5. **Test resource files** - Configuration files for tests only

### Files to INCLUDE in Patching
1. **Production source code:** `src/main/java/**/*.java`
2. **Core modules:** `core/src/main/`, `web/src/main/`
3. **Support modules:** `support/*/src/main/`
4. **Exclude samples:** Samples are example code, not production

### Validation Strategy
When validating patches:
1. Patches should NOT modify any file matching `**/src/test/**`
2. Patches should NOT modify `*Test.java` or `*Test.groovy` files
3. Run `mvn clean test` to ensure patches don't break existing tests
4. Focus patches on `src/main/java/**` directories only

## 8. Module Dependency Graph

```
shiro-root (parent POM)
├── core (fundamental security APIs)
├── web (web/servlet integration)
├── support/
│   ├── aspectj (AspectJ AOP support)
│   ├── ehcache (Caching support)
│   ├── guice (Google Guice DI)
│   ├── spring (Spring Framework)
│   ├── cas (CAS SSO - no tests)
│   └── quartz (Quartz scheduling - no tests found)
├── samples/ (example applications)
│   ├── aspectj
│   ├── web
│   ├── spring
│   ├── spring-client
│   ├── spring-hibernate
│   └── quickstart
└── tools/ (command-line tools)
    └── hasher
```

## 9. Key Findings

1. **Total Test Files:** 142 (109 Java + 33 Groovy)
2. **Test Framework:** JUnit 4.8.2 with Groovy support
3. **Test Distribution:** Heavily concentrated in `core` module (103 files)
4. **Test Coverage:** Comprehensive unit tests across all major components
5. **Integration Tests:** Present in samples and web modules
6. **Test Helpers:** Multiple test helper classes and base test classes
7. **Build System:** Standard Maven multi-module project structure

## 10. Conclusion

This analysis provides a complete inventory of all test-related files in the Apache Shiro project. The comprehensive patch exclude list ensures that CRS patch generation systems will avoid modifying test code, focusing only on production source code in `src/main/java` directories. The test execution commands enable validation of generated patches against the existing test suite.

---

**Generated by:** CRSBench Test Analysis Agent
**For:** atlanta-shiro-full-01 benchmark
**Purpose:** CRS patch generation and vulnerability repair evaluation
