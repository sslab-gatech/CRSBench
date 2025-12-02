# Apache POI Test Analysis

## Project Information

**Project Name:** Apache POI
**Repository Path:** `/mnt/ssd1/acorn421/team-atlanta/repos/cp-java-apache-poi-src-9f2fa574`
**Benchmark Directory:** `benchmarks/atlanta-apache-poi-full-01`
**Base Commit:** `9f2fa57409db9a8e6241dadb0fcec18d8d881f52`
**Language:** Java
**Version:** 5.4.2-SNAPSHOT

## Build System

### Primary Build Tool
**Gradle** (with legacy Ant support via build.xml)

- **Gradle Version:** 8.14.2
- **Build Files:**
  - Root: `build.gradle`, `settings.gradle`
  - Module-specific: `poi/build.gradle`, `poi-ooxml/build.gradle`, `poi-scratchpad/build.gradle`, etc.

### Test Framework
**JUnit 5 (Jupiter)** - Version 5.13.1

Additional test dependencies:
- Mockito 4.11.0
- Hamcrest 3.0
- Log4j 2.24.3 (for test logging)

## Test Directory Structure

The project follows a multi-module Maven/Gradle structure with separate source sets:

```
cp-java-apache-poi-src-9f2fa574/
├── poi/src/test/java/                    # Core POI tests (601 files)
├── poi-ooxml/src/test/java/              # OOXML format tests (308 files)
├── poi-scratchpad/src/test/java/         # Legacy format tests (200 files)
├── poi-integration/src/test/java/        # Integration/stress tests (30 files)
├── poi-excelant/src/test/java/           # Excelant tests
├── poi-examples/src/test/java/           # Example tests
└── osgi/src/test/java/                   # OSGi bundle tests
```

### Total Test Files
- **Estimated test files:** ~1,085 Java test files with "Test" in filename
- **Actual JUnit test classes:** ~1,020+ test classes

## Test Identification Patterns

### Naming Conventions
Tests in Apache POI follow standard Java test naming patterns:

1. **Test classes:**
   - `Test*.java` (e.g., `TestPOIDocument.java`)
   - `*Test.java` (e.g., `SheetRangeEvaluatorTest.java`)

2. **Base test classes (abstract):**
   - `BaseTest*.java` (42+ classes)
   - Examples: `BaseTestBorderStyle`, `BaseTestCellUtil`, `BaseTestWorkbook`
   - These are abstract test classes extended by concrete implementations

3. **Test utilities and helpers:**
   - `POIDataSamples.java` - Test data helper
   - `POITestCase.java` - Base test case utilities
   - `OpenXML4JTestDataSamples.java` - OOXML test data helper

## Test Execution Configuration

### Gradle Test Task Configuration
From `build.gradle` (lines 327-444):

```groovy
test {
    // JUnit 5 Platform
    useJUnitPlatform()

    // System properties
    systemProperty "user.language", "en"
    systemProperty "user.country", "US"
    systemProperty "POI.testdata.path", "../test-data"

    // Heap settings
    minHeapSize = "128m"
    maxHeapSize = "2g"

    // Parallel execution (non-CI)
    jvmArgs += [
        '-Djunit.jupiter.execution.parallel.enabled=true',
        '-Djunit.jupiter.execution.parallel.config.strategy=dynamic'
    ]
}
```

### Excluded Test Classes
The build explicitly excludes certain test patterns (build.gradle lines 344-351):

```groovy
exclude '**/BaseTestBorderStyle.class'
exclude '**/BaseTestCellUtil.class'
exclude '**/TestUnfixedBugs.class'
exclude '**/TestOneFile.class'

// Exclude Test Suites
exclude '**/All*Tests.class'
exclude '**/HSSFTests.class'
```

### Why These Tests Are Excluded

1. **Base classes** (`BaseTest*`):
   - Abstract test classes that provide common functionality
   - Not executable tests themselves
   - Extended by concrete test implementations

2. **TestUnfixedBugs**:
   - Contains tests for known unfixed bugs
   - Located in:
     - `poi/src/test/java/org/apache/poi/hssf/usermodel/TestUnfixedBugs.java`
     - `poi-ooxml/src/test/java/org/apache/poi/xssf/usermodel/TestUnfixedBugs.java`
   - These tests document bugs but are not expected to pass

3. **TestOneFile**:
   - Utility test class for testing single files during development
   - Not part of the regular test suite

4. **Test suites** (`All*Tests`, `HSSFTests`):
   - Legacy test suite classes
   - JUnit 5 auto-discovers tests, so suites are redundant

## Test Modules Breakdown

### 1. Core Module (poi)
**Location:** `poi/src/test/java/`
**Test Count:** 601 files

**Key test packages:**
- `org.apache.poi.hssf.*` - HSSF (Excel 97-2003) format tests
- `org.apache.poi.ss.*` - Common spreadsheet API tests
- `org.apache.poi.poifs.*` - POI File System tests
- `org.apache.poi.hpsf.*` - Property set tests
- `org.apache.poi.ddf.*` - Drawing format tests
- `org.apache.poi.util.*` - Utility tests

**Notable test classes:**
- Formula evaluation tests
- Cell formatting tests
- Workbook/Sheet/Row/Cell tests
- File format parsing tests

### 2. OOXML Module (poi-ooxml)
**Location:** `poi-ooxml/src/test/java/`
**Test Count:** 308 files

**Key test packages:**
- `org.apache.poi.xssf.*` - XSSF (Excel 2007+) tests
- `org.apache.poi.xwpf.*` - XWPF (Word 2007+) tests
- `org.apache.poi.xslf.*` - XSLF (PowerPoint 2007+) tests
- `org.apache.poi.openxml4j.*` - OpenXML packaging tests
- `org.apache.poi.poifs.crypt.*` - Encryption/signing tests

**Notable test features:**
- Streaming tests (SXSSF)
- Event-based parsing tests
- Digital signature tests
- OPC (Open Packaging Convention) tests

### 3. Scratchpad Module (poi-scratchpad)
**Location:** `poi-scratchpad/src/test/java/`
**Test Count:** 200 files

**Key test packages:**
- `org.apache.poi.hslf.*` - HSLF (PowerPoint 97-2003) tests
- `org.apache.poi.hwpf.*` - HWPF (Word 97-2003) tests
- `org.apache.poi.hdgf.*` - HDGF (Visio) tests
- `org.apache.poi.hsmf.*` - HSMF (Outlook MSG) tests
- `org.apache.poi.hmef.*` - HMEF (TNEF) tests
- `org.apache.poi.hpbf.*` - HPBF (Publisher) tests
- `org.apache.poi.hwmf.*` - HWMF (WMF) tests
- `org.apache.poi.hemf.*` - HEMF (EMF) tests

### 4. Integration Module (poi-integration)
**Location:** `poi-integration/src/test/java/org/apache/poi/stress/`
**Test Count:** 30 files

**Purpose:** Stress/integration tests that process all test-data files

**Key classes:**
- `BaseIntegrationTest.java` - Base integration test
- `*FileHandler.java` - Format-specific handlers (HDGF, HSLF, HSSF, HWPF, etc.)
- These tests load and process all available test files for robustness testing

## Test Data

**Location:** `test-data/` directory (root level)

The project includes comprehensive test data organized by format:
- `test-data/spreadsheet/` - Excel files
- `test-data/document/` - Word files
- `test-data/slideshow/` - PowerPoint files
- `test-data/diagram/` - Visio files
- `test-data/publisher/` - Publisher files
- `test-data/hsmf/` - Outlook MSG files
- `test-data/hmef/` - TNEF files
- `test-data/hpsf/` - Property set files

These test data files are:
1. Used by unit tests for validation
2. Packaged as fuzzer seed corpus in OSS-Fuzz build
3. Referenced via system property: `POI.testdata.path=../test-data`

## Test Execution Commands

### Run All Tests
```bash
# Using Gradle
./gradlew test

# Run tests for specific module
./gradlew :poi:test
./gradlew :poi-ooxml:test
./gradlew :poi-scratchpad:test
./gradlew :poi-integration:test
```

### Run Specific Test Class
```bash
./gradlew test --tests "org.apache.poi.hssf.usermodel.TestBugs"
```

### Skip Tests During Build
```bash
# Used in OSS-Fuzz build.sh
./gradlew publishToMavenLocal -x javadoc -x test
```

## Build Configuration for Fuzzing

From `.oss-fuzz/build.sh`:

```bash
# Gradle flags used during fuzzing build
GRADLE_FLAGS="-x javadoc -x test -Dfile.encoding=UTF-8 \
  -Porg.gradle.java.installations.fromEnv=JAVA_HOME_8,JAVA_HOME_11 \
  --console=plain"

# Tests are explicitly skipped during fuzzer build
./gradlew publishToMavenLocal ${GRADLE_FLAGS}
```

## Disabled/Ignored Tests

**Count:** 108 occurrences of `@Disabled` or `@Ignore` across 49 files

**Common reasons for disabled tests:**
1. Flaky tests that need investigation
2. Tests requiring specific external resources
3. Performance/memory-intensive tests
4. Tests for features under development
5. Known failing tests pending fixes

**Notable disabled test files:**
- `TestUnfixedBugs.java` (HSSF and XSSF versions)
- Various `TestBugs.java` files with individual disabled test methods
- Memory/performance tests in SXSSF module
- Some digital signature tests requiring certificates

## Comprehensive Patch Exclude List

Based on the analysis, here is the comprehensive list of patterns to exclude when generating patches:

### Test Files and Directories

```yaml
# Test source directories
- '**/src/test/**'
- 'poi/src/test/**'
- 'poi-ooxml/src/test/**'
- 'poi-scratchpad/src/test/**'
- 'poi-integration/src/test/**'
- 'poi-excelant/src/test/**'
- 'poi-examples/src/test/**'
- 'osgi/src/test/**'

# Test data directory
- 'test-data/**'

# Java test patterns
- '**/*Test.java'
- '**/Test*.java'
- '**/*Tests.java'
- '**/*TestCase.java'
- '**/*Spec.java'

# Base test classes
- '**/BaseTest*.java'
- '**/Abstract*Test*.java'

# Test utilities
- '**/POITestCase.java'
- '**/POIDataSamples.java'
- '**/*TestDataSamples.java'

# Integration/stress test handlers
- 'poi-integration/src/test/java/org/apache/poi/stress/**'

# Unfixed bugs test files
- '**/TestUnfixedBugs.java'
```

### Build and Configuration Files

```yaml
# Build system files
- 'build.gradle'
- 'build.xml'
- 'settings.gradle'
- 'gradle.properties'
- 'wrapper.gradle'
- '*/build.gradle'
- 'gradlew'
- 'gradlew.bat'
- 'gradle/**'
- '.gradle/**'

# Maven/Ivy
- 'pom.xml'
- '*/pom.xml'

# Build output
- 'build/**'
- '*/build/**'
- 'out/**'
- 'target/**'
- '*/target/**'
```

### OSS-Fuzz Infrastructure

```yaml
# OSS-Fuzz specific
- '.oss-fuzz/**'
- 'build.sh'
- 'Dockerfile'
- 'project.yaml'
```

### Documentation and Metadata

```yaml
# Documentation
- '*.md'
- '*.rst'
- 'README*'
- 'NOTICE*'
- 'LICENSE*'
- 'KEYS'
- 'docs/**'
- 'documentation/**'
- 'legal/**'

# Metadata
- '.gitignore'
- '.gitattributes'
- '*.iml'
- '.idea/**'
- '.settings/**'
- '.classpath'
- '.project'
- '*.rdf'
```

### Configuration and Resources

```yaml
# CI/CD
- 'jenkins/**'
- '.github/**'
- '.travis.yml'
- '.circleci/**'

# Resources that might contain test configurations
- '**/test-resources/**'
- '**/src/test/resources/**'
```

## Complete YAML Patch Exclude List

Here is the complete patch_exclude_list for the meta.yaml:

```yaml
patch_exclude_list:
  # Build system files
  - build.sh
  - Makefile
  - CMakeLists.txt
  - 'configure*'
  - '*.ac'
  - '*.am'
  - build.gradle
  - build.xml
  - settings.gradle
  - gradle.properties
  - wrapper.gradle
  - '*/build.gradle'
  - gradlew
  - gradlew.bat
  - gradle/**
  - .gradle/**
  - pom.xml
  - '*/pom.xml'

  # OSS-Fuzz infrastructure
  - .oss-fuzz/**
  - .aixcc/**
  - Dockerfile
  - project.yaml

  # Version control
  - .gitignore
  - .gitattributes
  - .git/**

  # Documentation
  - '*.md'
  - '*.rst'
  - README*
  - NOTICE*
  - LICENSE*
  - KEYS
  - docs/**
  - documentation/**
  - legal/**
  - SECURITY.md
  - doap_POI.rdf

  # Test directories (comprehensive)
  - test/**
  - tests/**
  - '**/src/test/**'
  - poi/src/test/**
  - poi-ooxml/src/test/**
  - poi-scratchpad/src/test/**
  - poi-integration/src/test/**
  - poi-excelant/src/test/**
  - poi-examples/src/test/**
  - osgi/src/test/**
  - test-data/**

  # Test files by pattern
  - '**/*test*.java'
  - '**/*Test.java'
  - '**/Test*.java'
  - '**/*Tests.java'
  - '**/*TestCase.java'
  - '**/*Spec.java'
  - '**/BaseTest*.java'
  - '**/Abstract*Test*.java'
  - '**/POITestCase.java'
  - '**/POIDataSamples.java'
  - '**/*TestDataSamples.java'
  - '**/TestUnfixedBugs.java'

  # C/C++ test patterns (for completeness)
  - '**/*test*.c'
  - '**/*test*.cc'
  - '**/*test*.cpp'
  - '**/*test*.h'

  # Build outputs
  - build/**
  - '*/build/**'
  - out/**
  - target/**
  - '*/target/**'
  - dist/**
  - lib/**
  - lib.stored/**

  # IDE files
  - '*.iml'
  - '*.ipr'
  - '*.iws'
  - .idea/**
  - .settings/**
  - .classpath
  - .project
  - .vscode/**

  # CI/CD
  - jenkins/**
  - .github/**
  - .travis.yml
  - .circleci/**

  # OSGi
  - osgi/**

  # Example and integration code
  - poi-examples/**
  - poi-integration/**

  # Patch and temporary files
  - patch.xml
  - '*.patch'
  - '*.diff'
  - '*.tmp'
  - '*.swp'
  - '*.log'
  - '*.launch'
```

## Summary

**Build System:** Gradle 8.14.2
**Test Framework:** JUnit 5 (Jupiter) 5.13.1
**Total Test Files:** ~1,085 Java test files
**Test Modules:** 7 modules with tests (poi, poi-ooxml, poi-scratchpad, poi-integration, poi-excelant, poi-examples, osgi)
**Test Execution:** `./gradlew test` or module-specific with `:module:test`
**Tests Skipped in Fuzzing Build:** Yes, via `-x test` flag

**Key Points for Patch Generation:**
1. Exclude all `src/test/` directories across all modules
2. Exclude test data directory (`test-data/`)
3. Exclude base/abstract test classes (not executable tests)
4. Exclude build system files (Gradle, Ant)
5. Exclude OSS-Fuzz infrastructure files
6. Exclude documentation and IDE configuration
7. Focus patches only on production code in `src/main/` directories

**Test Exclusions in Build:**
- Abstract base test classes
- Test suite classes
- Unfixed bugs test class
- Development utility test classes

This analysis provides complete coverage of the test infrastructure for the Apache POI project, enabling accurate exclusion of test-related files during patch generation for vulnerability fixing.
