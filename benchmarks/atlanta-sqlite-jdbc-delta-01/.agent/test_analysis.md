# Test Analysis for SQLite JDBC Project

**Project:** sqlite-jdbc-02a9800d
**Benchmark:** atlanta-sqlite-jdbc-delta-01
**Analysis Date:** 2024
**Repository Path:** `/home/acorn421/work/team-atlanta/afc-repos/sqlite-jdbc-02a9800d`

---

## Executive Summary

This document provides a comprehensive analysis of the test infrastructure for the SQLite JDBC project, including unit tests, functional tests, test frameworks, build system configuration, and patch exclusion recommendations for CRS (Cyber Reasoning System) evaluation.

**Key Findings:**
- **Build System:** Maven (pom.xml) with Make for native components
- **Test Framework:** JUnit 5 (Jupiter) with AssertJ, Mockito, JUnit Pioneer, and ArchUnit
- **Total Test Files:** 41 Java test files
- **Test Classes:** 39 test classes with 435+ @Test annotated methods
- **Test Utility Files:** 2 (Utils.java, NativeDBHelper.java)

---

## 1. Build System and Test Framework

### 1.1 Build System

**Primary Build System:** Apache Maven

- **Build File:** `pom.xml` at project root
- **Maven Version Requirement:** 3.2.5+
- **Java Version:** Java 8 (source/target), with Java 11+ required for build
- **Multi-Release JAR:** Supports Java 9+ with separate source directory

**Secondary Build System:** GNU Make (for native SQLite components)

- **Makefile:** Used for building native JNI libraries
- **Native Build Target:** `make native`
- **Test Target:** `make test` (delegates to `mvn test`)

### 1.2 Test Framework

**Test Framework:** JUnit 5.12.2 (JUnit Jupiter)

**Test Dependencies:**
```xml
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.12.2</version>
    <scope>test</scope>
</dependency>
```

**Additional Test Libraries:**

1. **AssertJ 3.27.3** - Fluent assertion library
   ```xml
   <groupId>org.assertj</groupId>
   <artifactId>assertj-core</artifactId>
   ```

2. **JUnit Pioneer 2.3.0** - Extension pack for JUnit
   ```xml
   <groupId>org.junit-pioneer</groupId>
   <artifactId>junit-pioneer</artifactId>
   ```

3. **Mockito 5.17.0** - Mocking framework
   ```xml
   <groupId>org.mockito</groupId>
   <artifactId>mockito-core</artifactId>
   ```

4. **ArchUnit 1.4.0** - Architecture testing library
   ```xml
   <groupId>com.tngtech.archunit</groupId>
   <artifactId>archunit-junit5</artifactId>
   ```

5. **Logback Classic 1.2.13** - Required by ArchUnit

**Test Runner:** Maven Surefire Plugin 3.5.3
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>3.5.3</version>
</plugin>
```

---

## 2. Test File Inventory

### 2.1 Test Directory Structure

```
src/test/
├── java/
│   └── org/
│       └── sqlite/
│           ├── architecture/          # Architecture tests
│           ├── core/                  # Test helpers
│           └── util/                  # Utility tests
└── resources/
    ├── META-INF/native-image/        # GraalVM test config
    └── org/sqlite/                    # Test data files
```

### 2.2 Complete Test File List (41 files)

#### Core JDBC Tests (19 files)
1. `src/test/java/org/sqlite/JDBCTest.java` - 12 @Test methods
2. `src/test/java/org/sqlite/ConnectionTest.java` - 24 @Test methods
3. `src/test/java/org/sqlite/StatementTest.java` - 46 @Test methods
4. `src/test/java/org/sqlite/PrepStmtTest.java` - 46 @Test methods
5. `src/test/java/org/sqlite/ResultSetTest.java` - 21 @Test methods
6. `src/test/java/org/sqlite/QueryTest.java` - 15 @Test methods
7. `src/test/java/org/sqlite/InsertQueryTest.java` - 3 @Test methods
8. `src/test/java/org/sqlite/TransactionTest.java` - 15 @Test methods
9. `src/test/java/org/sqlite/SavepointTest.java` - 4 @Test methods
10. `src/test/java/org/sqlite/DBMetaDataTest.java` - 49 @Test methods
11. `src/test/java/org/sqlite/RSMetaDataTest.java` - 11 @Test methods
12. `src/test/java/org/sqlite/TypeMapTest.java` - 2 @Test methods
13. `src/test/java/org/sqlite/ErrorMessageTest.java` - 5 @Test methods
14. `src/test/java/org/sqlite/FetchSizeTest.java` - 1 @Test method
15. `src/test/java/org/sqlite/CachedRowSetTest.java` - 1 @Test method
16. `src/test/java/org/sqlite/ResultSetWithoutResultsTest.java` - 1 @Test method
17. `src/test/java/org/sqlite/PreparedStatementThreadTest.java` - 2 @Test methods
18. `src/test/java/org/sqlite/ReadUncommittedTest.java` - 4 @Test methods
19. `src/test/java/org/sqlite/MetadataLeakTest.java` - 1 @Test method

#### SQLite Feature Tests (9 files)
20. `src/test/java/org/sqlite/ExtensionTest.java` - 4 @Test methods
21. `src/test/java/org/sqlite/ExtendedCommandTest.java` - 2 @Test methods
22. `src/test/java/org/sqlite/BackupTest.java` - 4 @Test methods
23. `src/test/java/org/sqlite/SerializeTest.java` - 11 @Test methods
24. `src/test/java/org/sqlite/CollationTest.java` - 5 @Test methods
25. `src/test/java/org/sqlite/UDFTest.java` - 16 @Test methods
26. `src/test/java/org/sqlite/UDFCustomErrorTest.java` - 1 @Test method
27. `src/test/java/org/sqlite/JSON1Test.java` - 57 @Test methods
28. `src/test/java/org/sqlite/MathFunctionsTest.java` - 32 @Test methods

#### Handler and Listener Tests (3 files)
29. `src/test/java/org/sqlite/BusyHandlerTest.java` - 4 @Test methods
30. `src/test/java/org/sqlite/ProgressHandlerTest.java` - 4 @Test methods
31. `src/test/java/org/sqlite/ListenerTest.java` - 6 @Test methods

#### Configuration and DataSource Tests (4 files)
32. `src/test/java/org/sqlite/SQLiteConfigTest.java` - 3 @Test methods
33. `src/test/java/org/sqlite/SQLiteDataSourceTest.java` - 4 @Test methods
34. `src/test/java/org/sqlite/SQLiteConnectionPoolDataSourceTest.java` - 2 @Test methods
35. `src/test/java/org/sqlite/SQLiteJDBCLoaderTest.java` - 4 @Test methods

#### Special Tests (2 files)
36. `src/test/java/org/sqlite/MultipleClassLoaderTest.java` - 1 @Test method
    - **Note:** Excluded in native profile - Cannot run in native mode

#### Architecture Tests (2 files)
37. `src/test/java/org/sqlite/architecture/CodingRulesTest.java` - Multiple @ArchTest rules
38. `src/test/java/org/sqlite/architecture/TestCodingRulesTest.java` - Multiple @ArchTest rules

#### Utility Tests (1 file)
39. `src/test/java/org/sqlite/util/OSInfoTest.java` - 12 @Test methods

#### Test Helper/Utility Files (2 files - not test classes)
40. `src/test/java/org/sqlite/Utils.java` - Test utility class
41. `src/test/java/org/sqlite/core/NativeDBHelper.java` - Native test helper

### 2.3 Test Statistics

- **Total Java Files:** 41
- **Actual Test Classes:** 39 (2 are utility files)
- **Total @Test Methods:** 435+
- **Architecture Tests:** 2 files with multiple @ArchTest rules
- **Test Resource Files:** 6 files
  - `testdb.jar`
  - `sample.db`
  - `attach_test.db`
  - GraalVM native-image configuration files (3)

---

## 3. Test Resources

### 3.1 Test Resource Files

Located in `src/test/resources/`:

1. **Database Files:**
   - `org/sqlite/testdb.jar` - Test database JAR
   - `org/sqlite/sample.db` - Sample SQLite database
   - `org/sqlite/attach_test.db` - Database for attachment tests

2. **GraalVM Native Image Configuration:**
   - `META-INF/native-image/org.xerial/sqlite-jdbc/resource-config.json`
   - `META-INF/native-image/org.xerial/sqlite-jdbc/reachability-metadata.json`
   - `META-INF/native-image/org.xerial/sqlite-jdbc/reflect-config.json`

### 3.2 Test Resource Configuration

From `pom.xml`:
```xml
<testResources>
    <testResource>
        <directory>src/test/java</directory>
        <excludes>
            <exclude>**/*.java</exclude>
        </excludes>
    </testResource>
    <testResource>
        <directory>src/test/resources</directory>
    </testResource>
</testResources>
```

---

## 4. Test Commands

### 4.1 Standard Test Commands

**Maven Test Command:**
```bash
mvn test
```

**Makefile Test Target:**
```bash
make test
```
(Delegates to `mvn test`)

### 4.2 Build Commands (from build.sh)

**OSS-Fuzz Build Command:**
```bash
# Build native components
make native

# Package with Maven (skip tests)
mvn clean package \
    -Dmaven.javadoc.skip=true \
    -DskipTests=true \
    -Dpmd.skip=true \
    -Dencoding=UTF-8 \
    -Dmaven.antrun.skip=true \
    -Dcheckstyle.skip=true \
    -DperformRelease=True \
    org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade
```

### 4.3 Test Exclusions

**Native Profile Test Exclusions:**

When running with `-P native` profile:
```xml
<excludes>
    <!--  Cannot run in native mode, classes under test cannot be found, class path is empty  -->
    <exclude>**/MultipleClassLoaderTest.java</exclude>
</excludes>
```

**Reason:** `MultipleClassLoaderTest` cannot run in GraalVM native mode due to classpath limitations.

### 4.4 Clean Commands

```bash
# Maven clean
mvn clean

# Makefile clean (includes native, java, and tests)
make clean
```

---

## 5. Test Classification

### 5.1 Unit Tests

**Category:** JDBC API Compliance Tests

Tests verifying correct implementation of JDBC interfaces:
- ConnectionTest
- StatementTest
- PrepStmtTest
- ResultSetTest
- DBMetaDataTest
- RSMetaDataTest
- TypeMapTest

**Category:** SQLite Feature Tests

Tests for SQLite-specific functionality:
- ExtensionTest - Extension loading
- BackupTest - Database backup API
- SerializeTest - Database serialization
- CollationTest - Custom collation
- UDFTest, UDFCustomErrorTest - User-defined functions
- JSON1Test - JSON1 extension (57 tests)
- MathFunctionsTest - Math functions (32 tests)

**Category:** Configuration Tests

Tests for datasource and configuration:
- SQLiteConfigTest
- SQLiteDataSourceTest
- SQLiteConnectionPoolDataSourceTest
- SQLiteJDBCLoaderTest

**Category:** Handler Tests

Tests for callback handlers:
- BusyHandlerTest
- ProgressHandlerTest
- ListenerTest

### 5.2 Functional Tests

**Category:** Query and Transaction Tests

Integration tests for SQL operations:
- QueryTest
- InsertQueryTest
- TransactionTest
- SavepointTest
- ExtendedCommandTest
- ReadUncommittedTest

**Category:** Error Handling Tests

Tests for error conditions:
- ErrorMessageTest
- ResultSetWithoutResultsTest
- MetadataLeakTest

**Category:** Concurrency Tests

- PreparedStatementThreadTest

### 5.3 Architecture Tests

**Static Analysis Tests:**
- `architecture/CodingRulesTest.java` - Enforces coding standards
- `architecture/TestCodingRulesTest.java` - Enforces test coding standards

Uses ArchUnit for:
- No access to standard streams (except OSInfo)
- No generic exceptions
- No Jodatime usage
- SLF4J logging enforcement

### 5.4 Utility and Support Tests

- `util/OSInfoTest.java` - OS detection utility tests
- `MultipleClassLoaderTest.java` - ClassLoader isolation test
- `FetchSizeTest.java` - Fetch size configuration
- `CachedRowSetTest.java` - Cached row sets

---

## 6. Comprehensive Patch Exclude List

### 6.1 Current Exclude List (from meta.yaml)

The current `patch_exclude_list` in `.oss-fuzz/.aixcc/meta.yaml`:

```yaml
patch_exclude_list:
- build.sh
- Makefile
- CMakeLists.txt
- configure*
- '*.ac'
- '*.am'
- .gitignore
- .aixcc/**
- '**/*test*.c'
- '**/*test*.cc'
- '**/*test*.cpp'
- '**/*test*.h'
- test/**
- tests/**
- docs/**
- '*.md'
- README*
```

### 6.2 Recommended Comprehensive Exclude List for Java Project

**Analysis:** The current exclude list is C/C++ focused. For this Java project, we need Java-specific exclusions.

**Recommended Enhanced Patch Exclude List:**

```yaml
patch_exclude_list:
# Build System Files
- build.sh
- Makefile
- Makefile.common
- pom.xml
- dependency-reduced-pom.xml
- CMakeLists.txt
- configure*
- '*.ac'
- '*.am'
- settings.xml
- maven-eclipse.xml

# Version Control and CI/CD
- .gitignore
- .hgignore
- .git/**
- .github/**
- .gitlab-ci.yml

# Project Metadata
- .aixcc/**
- .oss-fuzz/**

# Test Files - C/C++/C++
- '**/*test*.c'
- '**/*test*.cc'
- '**/*test*.cpp'
- '**/*test*.h'
- test/**
- tests/**

# Test Files - Java (NEW)
- '**/*Test.java'
- '**/*Tests.java'
- '**/Test*.java'
- src/test/**
- src/test/java/**
- src/test/resources/**

# Test Utility Files (NEW)
- '**/Utils.java'           # Test utility class
- '**/NativeDBHelper.java'  # Test helper

# Fuzzer Files
- '**/*Fuzzer.java'
- '**/*Fuzzer.class'

# Documentation
- docs/**
- '*.md'
- '*.adoc'
- README*
- CHANGELOG
- NEWS.md
- CONTRIBUTING.md
- LICENSE*
- NOTICE
- SECURITY.md
- USAGE.md
- '*.wiki'

# Build Artifacts and Target Directories
- target/**
- build/**
- out/**
- '*.class'
- '*.jar'
- '*.war'

# IDE and Editor Files
- .vscode/**
- .idea/**
- '*.iml'
- .classpath
- .project
- .settings/**
- '*.swp'
- '*.swo'
- '*~'

# Archive and Demo
- archive/**
- demo/**

# Docker and Container Files
- docker/**
- Dockerfile
- .dockerignore

# Release and Deployment
- jreleaser.yml

# Native Library Build Output (if present)
- lib/**/*.so
- lib/**/*.dylib
- lib/**/*.dll
```

### 6.3 Java-Specific Exclusion Patterns

**Critical Java Test Patterns to Exclude:**

1. **Test Class Patterns:**
   - `**/*Test.java` - Standard JUnit test naming
   - `**/*Tests.java` - Alternative plural form
   - `**/Test*.java` - Test prefix pattern

2. **Test Directory Patterns:**
   - `src/test/**` - All test sources
   - `src/test/java/**` - Java test sources
   - `src/test/resources/**` - Test resources

3. **Test Utility Files:**
   - Files in test directories that don't match test naming but are test utilities
   - Example: `src/test/java/org/sqlite/Utils.java`
   - Example: `src/test/java/org/sqlite/core/NativeDBHelper.java`

### 6.4 Rationale for Exclusions

**Why Exclude Test Files:**

1. **Not Production Code:** Test files are not part of the production codebase
2. **No Security Impact:** Vulnerabilities in test code don't affect deployed systems
3. **Different Quality Standards:** Test code follows different patterns (e.g., uses assertions)
4. **False Positives:** CRS may report issues in test utilities that are intentional
5. **Efficiency:** Reduces patch search space by ~41 Java files (435+ test methods)

**Why Exclude Build Files:**

1. **Not Runtime Code:** Build files are not executed in production
2. **Configuration Only:** Changes to build config don't affect vulnerability fixes
3. **Build System Specific:** Maven/Make files are not part of the application logic

**Why Exclude Documentation:**

1. **No Code Impact:** Documentation changes don't affect vulnerabilities
2. **Markdown/Text Files:** Non-executable content

### 6.5 Files That Should NOT Be Excluded

**Production Source Code:** Keep these in patch scope:
- `src/main/java/**/*.java` - Main production code
- `src/main/resources/**` - Production resources
- `src/main/ext/*.c` - SQLite extension C code

**Native Source Code:**
- SQLite amalgamation source (if modified)
- JNI wrapper code

---

## 7. Test Execution Profiles

### 7.1 Standard Profile

**Default Test Execution:**
```bash
mvn test
```

Runs all 39 test classes with 435+ test methods.

### 7.2 Native Profile

**GraalVM Native Image Testing:**
```bash
mvn test -P native
```

**Configuration:**
- Uses GraalVM Native Maven Plugin
- Excludes `MultipleClassLoaderTest.java`
- Special initialization for JUnit support
- Configures strict image heap mode

**Build Args:**
```xml
<arg>--initialize-at-build-time=org.junitpioneer.jupiter.issue.IssueExtensionExecutionListener</arg>
<arg>--initialize-at-build-time=org.junit.jupiter.engine.descriptor.ExclusiveResourceCollector$DefaultExclusiveResourceCollector</arg>
<arg>--initialize-at-build-time=org.junit.jupiter.api.parallel.ResourceLock</arg>
<arg>--initialize-at-build-time=org.junit.jupiter.api.parallel.ResourceLockTarget</arg>
<arg>--initialize-at-build-time=org.junit.jupiter.api.parallel.ResourceAccessMode</arg>
```

### 7.3 Native Exported Profile

```bash
mvn test -P native-exported
```

Adds export path configuration:
```xml
<buildArg>-Dorg.sqlite.lib.exportPath=${project.build.directory}</buildArg>
```

---

## 8. Test Dependencies and Requirements

### 8.1 Runtime Requirements for Tests

**Java Version:**
- Minimum: Java 11 (for running tests)
- Target: Java 8 (compatibility target)

**Native Library:**
- SQLite native library must be built and available
- Built via `make native` before tests run

**Database Files:**
- Test databases in `src/test/resources/org/sqlite/`

### 8.2 Test Dependency Graph

```
JUnit 5 (Jupiter)
├── AssertJ (assertions)
├── JUnit Pioneer (extensions)
├── Mockito (mocking)
└── ArchUnit (architecture testing)
    └── Logback (logging for ArchUnit)
```

### 8.3 Compile Options Tested

Tests verify SQLite compiled with:
- `JDBC_EXTENSIONS` - Custom JDBC extensions
- `ENABLE_MATH_FUNCTIONS` - Math function support
- `ENABLE_FTS3/FTS5` - Full-text search
- `ENABLE_RTREE` - R*Tree index
- `ENABLE_JSON1` - JSON support

---

## 9. Special Test Considerations

### 9.1 Architecture Tests

**ArchUnit Tests** (`architecture/` package):
- Enforce coding standards on production code
- Do not test runtime behavior
- Use static analysis of compiled classes
- May fail if production code violates architectural rules

**Rules Enforced:**
- No access to `System.out`/`System.err` (except OSInfo class)
- Must use SLF4J for logging
- No generic exception throwing
- No Jodatime usage

### 9.2 ClassLoader Tests

**MultipleClassLoaderTest:**
- Tests JDBC driver loading across multiple classloaders
- Cannot run in GraalVM native mode
- Explicitly excluded in native profile

### 9.3 Extension and Feature Tests

**Conditional Tests:**
- Some tests use JUnit Pioneer's `@assumeThat` to skip if features not compiled
- Example: Math functions tests skip if `ENABLE_MATH_FUNCTIONS` not present
- JSON1 tests skip if JSON1 extension not available

**Test Utilities:**
- `Utils.java` provides helper methods for checking compile options
- `assumeJdbcExtensions()` - Skip if JDBC extensions not compiled
- `assumeMathFunctions()` - Skip if math functions not compiled

---

## 10. Test Pattern Analysis

### 10.1 Common Test Patterns

**JDBC Test Pattern:**
```java
@Test
public void testFeature() throws Exception {
    try (Connection conn = DriverManager.getConnection("jdbc:sqlite:")) {
        Statement stat = conn.createStatement();
        // Test logic
    }
}
```

**Temporary File Pattern:**
```java
@Test
public void testWithFile(@TempDir File tempDir) throws Exception {
    File dbFile = new File(tempDir, "test.db");
    try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile)) {
        // Test with file-based database
    }
}
```

**Architecture Test Pattern:**
```java
@ArchTest
private final ArchRule ruleName = NO_CLASSES_SHOULD_...;
```

### 10.2 Test Naming Conventions

**Test Class Naming:**
- Pattern: `<Feature>Test.java`
- Examples: `ConnectionTest`, `StatementTest`, `BackupTest`

**Test Method Naming:**
- Pattern: Descriptive method names with `@Test` annotation
- No rigid naming convention (not `testXxx` style)
- Examples: `enableLoadExtensionTest()`, `majorVersion()`

### 10.3 Assertion Style

**Primary:** AssertJ fluent assertions
```java
assertThat(value).isEqualTo(expected);
assertThat(list).contains("JDBC_EXTENSIONS");
```

**Legacy:** Some tests may use JUnit assertions
```java
assertEquals(expected, actual);
assertTrue(condition);
```

---

## 11. Impact on CRS Evaluation

### 11.1 Test Files and Patch Generation

**Why Tests Should Be Excluded:**

1. **Scope of Vulnerability:** The vulnerabilities tracked in this benchmark are in production code (`src/main/java`), not test code

2. **POV Files:** The POVs (Proof of Vulnerabilities) target the SqliteConnectionFuzzer, not test cases

3. **False Positives:** CRS may suggest patches to test files that:
   - Use deprecated APIs intentionally for testing
   - Contain intentional "bad" code to test error handling
   - Have different quality standards than production code

4. **Efficiency:** Excluding 41 test files with 435+ test methods significantly reduces the search space

### 11.2 Vulnerability Context

**From meta.yaml:**

- **Harness:** `SqliteConnectionFuzzer.java`
- **Vulnerabilities:**
  - `cpv_0`: ArrayIndexOutOfBoundsException
  - `cpv_1`: AddressSanitizer free error (JNI/native code issue)

**Patch Scope:**
- Production Java code: `src/main/java/org/sqlite/**`
- Native JNI code: JNI wrappers and SQLite extensions
- Should NOT include: `src/test/**`

### 11.3 Build System Considerations

**Maven Skip Tests:**
The OSS-Fuzz build already skips tests with `-DskipTests=true`, confirming tests are not part of the production build.

**Test Compilation:**
Tests may be compiled but not executed during fuzzing builds.

---

## 12. Recommendations

### 12.1 For CRS Configuration

1. **Use Enhanced Patch Exclude List:** Replace current C/C++-focused list with Java-specific patterns

2. **Verify Exclusions:** Ensure CRS respects:
   - `src/test/**` directory exclusion
   - `**/*Test.java` file pattern exclusion
   - Test utility files (Utils.java, NativeDBHelper.java)

3. **Focus on Production Code:** Direct CRS to patch scope:
   - `src/main/java/org/sqlite/**/*.java`
   - Native JNI wrapper code (if applicable)

### 12.2 For Benchmark Validation

1. **Test Execution Verification:**
   ```bash
   cd /home/acorn421/work/team-atlanta/afc-repos/sqlite-jdbc-02a9800d
   mvn clean test
   ```
   Should pass all tests in baseline commit.

2. **Fuzzer Execution:**
   ```bash
   # Build should complete without errors
   .oss-fuzz/build.sh
   ```

3. **POV Verification:**
   - Verify POV files trigger documented vulnerabilities
   - Test with SqliteConnectionFuzzer

### 12.3 For Meta.yaml Update

**Proposed Changes:**

```yaml
patch_exclude_list:
# Build system
- build.sh
- Makefile
- Makefile.common
- pom.xml
- dependency-reduced-pom.xml
- settings.xml
- maven-eclipse.xml

# Version control
- .gitignore
- .hgignore
- .git/**

# Project metadata
- .aixcc/**
- .oss-fuzz/**

# Test files - Java (UPDATED)
- '**/*Test.java'
- '**/*Tests.java'
- '**/Test*.java'
- src/test/**

# Test files - C/C++ (keep for native code)
- '**/*test*.c'
- '**/*test*.cc'
- '**/*test*.cpp'
- '**/*test*.h'
- test/**
- tests/**

# Fuzzer files
- '**/*Fuzzer.java'

# Documentation
- docs/**
- '*.md'
- '*.adoc'
- README*
- CHANGELOG
- NEWS.md
- CONTRIBUTING.md
- LICENSE*
- NOTICE
- SECURITY.md
- USAGE.md
- '*.wiki'

# Build artifacts
- target/**
- archive/**
- demo/**
- docker/**
- lib/**/*.so
- lib/**/*.dylib
- lib/**/*.dll

# Release config
- jreleaser.yml
```

---

## 13. Appendix

### 13.1 File Counts Summary

| Category | Count | Details |
|----------|-------|---------|
| Total Test Files | 41 | All .java files in src/test |
| Test Classes | 39 | Classes with @Test methods |
| Test Utility Files | 2 | Utils.java, NativeDBHelper.java |
| Test Methods | 435+ | @Test annotated methods |
| Test Resource Files | 6 | Databases + GraalVM config |
| Architecture Tests | 2 | ArchUnit-based tests |

### 13.2 Test Coverage by Category

| Category | Files | Test Methods |
|----------|-------|--------------|
| JDBC API Tests | 19 | ~200 |
| SQLite Features | 9 | ~130 |
| Handlers/Listeners | 3 | ~14 |
| Config/DataSource | 4 | ~13 |
| Architecture | 2 | ~10 @ArchTest |
| Special/Utility | 2 | ~14 |

### 13.3 Key Test Files Reference

**Most Comprehensive Test Suites:**
1. JSON1Test.java - 57 test methods
2. DBMetaDataTest.java - 49 test methods
3. PrepStmtTest.java - 46 test methods
4. StatementTest.java - 46 test methods
5. MathFunctionsTest.java - 32 test methods

### 13.4 Documentation References

**In Repository:**
- `README.adoc` - Project overview
- `USAGE.md` - Usage documentation
- `CONTRIBUTING.md` - Contribution guidelines
- `SECURITY.md` - Security policy

**Maven POM:**
- `pom.xml` - Complete build configuration
- Line 134-136: Surefire plugin configuration
- Line 376-380: Native profile test exclusions

**Build Scripts:**
- `.oss-fuzz/build.sh` - OSS-Fuzz build script
- `Makefile` - Native build targets

---

## Conclusion

This analysis provides a comprehensive overview of the SQLite JDBC test infrastructure. The project uses modern Java testing frameworks (JUnit 5, AssertJ) with 39 test classes containing 435+ test methods.

**Key Takeaway for CRS:** The current `patch_exclude_list` must be updated with Java-specific patterns to properly exclude the 41 test files in `src/test/` directory, focusing CRS patch generation on production code in `src/main/java/`.

**Recommended Action:** Update `.aixcc/meta.yaml` with the enhanced patch exclude list provided in Section 6.2.

---

**Analysis Complete**
**Document Version:** 1.0
**Total Test Files Analyzed:** 41
**Total Test Methods Documented:** 435+
