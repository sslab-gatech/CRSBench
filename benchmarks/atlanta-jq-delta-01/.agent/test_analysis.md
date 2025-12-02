# Test Analysis for jq (atlanta-jq-delta-01)

## Project Overview

**Project**: jq - A lightweight command-line JSON processor
**Repository Path**: `/mnt/ssd1/acorn421/team-atlanta/repos/cp-c-jq-b8d58e2b`
**Language**: C/C++
**Build System**: Autotools (autoconf/automake)
**Test Framework**: Custom test framework with shell scripts

## Build System Analysis

### Build Configuration
- **Primary Build System**: Autotools (configure.ac, Makefile.am)
- **Build Commands**:
  ```bash
  autoreconf -fi
  ./configure --with-oniguruma=builtin
  make -j$(nproc)
  make check
  ```
- **Test Execution**: `make check` runs test suite via `TESTS` variable in Makefile.am

### Build Files Identified
- `configure.ac` - Autoconf configuration
- `Makefile.am` - Automake makefile template
- `build/` - Build directory
- `config/` - Configuration helper scripts
- `m4/` - M4 macros for autoconf

## Test Infrastructure

### Test Framework
- **Type**: Custom test framework implemented in C (`src/jq_test.c`)
- **Test Runner**: Shell scripts that invoke the jq binary with test data files
- **Test Data Format**: Text files with test case specifications (.test files)

### Test Categories

#### 1. Unit Tests (src/jq_test.c)
**File**: `src/jq_test.c` (14,286 bytes, 494 lines)

**Purpose**: Embedded unit tests for core data structures and JSON parser

**Test Functions**:
- `jv_test()` - Tests for jq value types (lines 334-493)
  - JSON parser regression tests
  - Array and number operations
  - String operations (equality, hashing, formatting)
  - Object operations (get, set, copy-on-write)
  - Reference counting and memory management

- `run_jq_tests()` - Test executor for .test files (lines 76-249)
  - Compiles jq programs from test files
  - Executes programs with test inputs
  - Validates outputs against expected results
  - Handles error cases (%%FAIL markers)

- `run_jq_pthread_tests()` - Multi-threading tests (lines 304-331)
  - Tests thread safety with 3 concurrent threads
  - Validates concurrent jq_state usage

**Invocation**: Tests run via `jq --run-tests <testfile>` CLI option

#### 2. Functional Tests (Shell-Based)

##### Test Scripts (in tests/)
1. **jqtest** (`tests/jqtest`)
   - Runs main test suite from `tests/jq.test`
   - Command: `$JQ -L "$mods" --run-tests $JQTESTDIR/jq.test`
   - Uses valgrind if available and not disabled

2. **mantest** (`tests/mantest`)
   - Tests examples from manual documentation
   - Command: `$JQ -L "$mods" --run-tests $JQBASEDIR/tests/man.test`
   - Validates documentation examples

3. **manonigtest** (`tests/manonigtest`)
   - Tests for Oniguruma regex functionality
   - Command: `$JQ --run-tests $JQTESTDIR/manonig.test`
   - Only runs if Oniguruma support enabled

4. **onigtest** (`tests/onigtest`)
   - Additional Oniguruma-specific tests
   - Command: `$JQ --run-tests $JQTESTDIR/onig.test`

5. **optionaltest** (`tests/optionaltest`)
   - Tests optional jq features
   - Command: `$JQ --run-tests $JQTESTDIR/optional.test`
   - Skipped on Windows (WIN32)

6. **base64test** (`tests/base64test`)
   - Base64 encoding/decoding tests
   - Command: `$JQ --run-tests $JQTESTDIR/base64.test`

7. **utf8test** (`tests/utf8test`)
   - UTF-8 handling tests
   - Uses `tests/utf8-truncate.jq` test file

8. **shtest** (`tests/shtest`, 20,367 bytes)
   - Comprehensive shell-based integration tests
   - Tests:
     - Constant folding optimization
     - Command-line options
     - I/O error handling (with libinject_errors.so)
     - File input with null bytes
     - jq filter (-f) tests
   - Error injection testing with LD_PRELOAD

##### Test Data Files
- `tests/jq.test` (40,026 bytes) - Main test suite data
- `tests/man.test` (12,890 bytes) - Manual example tests
- `tests/manonig.test` (1,592 bytes) - Oniguruma manual tests
- `tests/onig.test` (3,906 bytes) - Oniguruma tests
- `tests/optional.test` (617 bytes) - Optional feature tests
- `tests/base64.test` (712 bytes) - Base64 tests

##### Test Modules
**Location**: `tests/modules/`
- `a.jq`, `b/b.jq`, `c/c.jq`, `c/d.jq` - Module loading tests
- `lib/jq/e/e.jq`, `lib/jq/f.jq` - Library path tests
- `home1/.jq`, `home2/.jq/g.jq` - Home directory tests
- `shadow1.jq`, `shadow2.jq` - Module shadowing tests
- `syntaxerror/syntaxerror.jq` - Error handling tests
- `test_bind_order*.jq` - Binding order tests
- `data.json` - Test data

##### Support Files
- `tests/setup` - Common setup script for test runners
  - Configures environment variables
  - Sets up valgrind if available
  - Creates temporary directories
- `tests/onig.supp` - Valgrind suppressions for Oniguruma
- `tests/local.supp` - Local valgrind suppressions
- `tests/torture/input0.json` - Stress test input

##### Helper Test Scripts
- `tests/jq-f-test.sh` - Tests `-f` (filter file) option
- `tests/no-main-program.jq` - Test for programs without main
- `tests/yes-main-program.jq` - Test for programs with main

#### 3. Fuzzing Harnesses (OSS-Fuzz)

**Location**: `tests/jq_fuzz_*.c` and `tests/jq_fuzz_*.cpp`

These are NOT traditional tests but fuzzing harnesses for vulnerability discovery:

1. **jq_fuzz_compile.c** (570 bytes)
   - Fuzzes `jq_compile()` function
   - Tests compilation of arbitrary jq programs
   - Entry point: `LLVMFuzzerTestOneInput()`

2. **jq_fuzz_execute.cpp** (1,215 bytes)
   - Fuzzes full execution pipeline: compile → parse → execute
   - Uses FuzzedDataProvider for structured fuzzing
   - Tests: `jq_compile()`, `jv_parse()`, `jq_next()`

3. **jq_fuzz_fixed.cpp** (8,781 bytes)
   - **Contains vulnerability**: cpv_0 (stack-buffer-overflow)
   - Fuzzes with 258 predefined jq programs
   - Tests common jq patterns with random input data
   - Structured fuzzing with fixed program set

4. **jq_fuzz_load_file.c** (552 bytes)
   - Fuzzes file loading functionality
   - Tests `jv_load_file()` with arbitrary inputs

5. **jq_fuzz_parse.c** (456 bytes)
   - Fuzzes JSON parser (`jv_parse()`)
   - Tests parsing of arbitrary JSON-like inputs

6. **jq_fuzz_parse_extended.c** (708 bytes)
   - **Contains vulnerability**: cpv_1 (heap-buffer-overflow)
   - Extended parser fuzzing with additional flags
   - Tests `jv_parser_new()`, `jv_parser_set_buf()`, `jv_parser_next()`

7. **jq_fuzz_parse_stream.c** (491 bytes)
   - Fuzzes streaming JSON parser
   - Tests `jv_parser_new()` with JV_PARSE_STREAMING flag

**Note**: Fuzzing harnesses are built and executed by OSS-Fuzz infrastructure, not part of `make check`.

## Test Execution in Makefile

### Test Configuration (Makefile.am)
```makefile
TESTS = tests/mantest tests/jqtest tests/shtest tests/utf8test tests/base64test
if !WIN32
TESTS += tests/optionaltest
endif

# Additional tests if Oniguruma enabled
if WITH_ONIGURUMA
TESTS += tests/onigtest tests/manonigtest
endif
```

### Test Environment
```makefile
AM_TESTS_ENVIRONMENT = JQ=$(abs_builddir)/jq NO_VALGRIND=$(NO_VALGRIND)
```

### Valgrind Integration
- Enabled by default if valgrind is installed
- Disabled when: `NO_VALGRIND=1` or `--enable-asan` configured
- Suppressions: `tests/onig.supp`, `tests/local.supp`

### Optional Test Features
- **Address Sanitizer**: `--enable-asan` (disables valgrind)
- **UB Sanitizer**: `--enable-ubsan`
- **Code Coverage**: `--enable-gcov`
- **Error Injection**: `--enable-error-injection` (builds libinject_errors.so)

## Test Command Summary

### Running All Tests
```bash
make check
```

### Running Specific Tests
```bash
# Run main jq test suite
./tests/jqtest

# Run manual tests
./tests/mantest

# Run shell integration tests
./tests/shtest

# Run with specific test file
./jq --run-tests tests/jq.test

# Skip first N tests
./jq --run-tests tests/jq.test --skip 10

# Take only N tests
./jq --run-tests tests/jq.test --take 5
```

### Running Tests with Valgrind
```bash
NO_VALGRIND=0 make check
```

### Running Tests with Sanitizers
```bash
./configure --enable-asan
make check

./configure --enable-ubsan
make check
```

## Comprehensive Patch Exclude List

Based on the test analysis, here is the comprehensive list of files that should be excluded from patching:

```yaml
patch_exclude_list:
  # Build system files
  - build.sh
  - Makefile
  - Makefile.am
  - CMakeLists.txt
  - configure
  - configure.ac
  - '*.ac'
  - '*.am'
  - build/**
  - config/**
  - m4/**
  - scripts/**

  # Version control and documentation
  - .gitignore
  - .gitattributes
  - .gitmodules
  - .github/**
  - .aixcc/**
  - '*.md'
  - README*
  - AUTHORS
  - COPYING
  - ChangeLog
  - NEWS.md
  - SECURITY.md
  - KEYS
  - docs/**

  # Test files - Unit tests
  - src/jq_test.c

  # Test files - Fuzzing harnesses (NOT traditional tests but OSS-Fuzz harnesses)
  - tests/jq_fuzz_compile.c
  - tests/jq_fuzz_execute.cpp
  - tests/jq_fuzz_fixed.cpp
  - tests/jq_fuzz_load_file.c
  - tests/jq_fuzz_parse.c
  - tests/jq_fuzz_parse_extended.c
  - tests/jq_fuzz_parse_stream.c

  # Test files - Shell scripts and test runners
  - tests/setup
  - tests/jqtest
  - tests/mantest
  - tests/manonigtest
  - tests/onigtest
  - tests/optionaltest
  - tests/base64test
  - tests/utf8test
  - tests/shtest
  - tests/jq-f-test.sh

  # Test files - Test data and configurations
  - tests/*.test
  - tests/jq.test
  - tests/man.test
  - tests/manonig.test
  - tests/onig.test
  - tests/optional.test
  - tests/base64.test
  - tests/*.supp
  - tests/onig.supp
  - tests/local.supp

  # Test files - Test modules and support files
  - tests/modules/**
  - tests/torture/**
  - tests/*.jq
  - tests/utf8-truncate.jq
  - tests/no-main-program.jq
  - tests/yes-main-program.jq

  # Entire test directory (comprehensive exclusion)
  - test/**
  - tests/**

  # Error injection library (testing utility)
  - src/inject_errors.c

  # Build artifacts and generated files
  - '*.o'
  - '*.a'
  - '*.so'
  - '*.la'
  - '*.lo'
  - .libs/**
  - .deps/**

  # Package files
  - '*.spec'
  - jq.spec
  - '*.pc.in'
  - libjq.pc.in
  - Dockerfile
  - compile-ios.sh

  # Prebuilt files
  - '*.prebuilt'
  - jq.1.prebuilt

  # Submodules
  - modules/**
  - sig/**
```

## Analysis Notes

### Test File Classification
1. **Unit Tests**: `src/jq_test.c` - Embedded in library for internal testing
2. **Functional Tests**: Shell scripts in `tests/` directory that execute jq binary
3. **Fuzzing Harnesses**: `tests/jq_fuzz_*.{c,cpp}` - OSS-Fuzz integration (NOT traditional tests)
4. **Test Data**: `tests/*.test` files containing test specifications

### Key Observations
1. **No separate test binary**: Tests are integrated via `--run-tests` CLI flag
2. **Test data format**: Plain text files with test program, input, and expected output
3. **Valgrind integration**: Optional memory leak detection during test runs
4. **Error injection**: Optional LD_PRELOAD library for I/O error simulation
5. **Module system**: Tests include module loading/import functionality
6. **Documentation tests**: Manual examples are automatically tested (tests/man.test)

### Fuzzing Harnesses vs Tests
- Fuzzing harnesses (`jq_fuzz_*.c/cpp`) are NOT unit/functional tests
- They are specialized entry points for libFuzzer/AFL fuzzing
- Built separately by OSS-Fuzz, not by `make check`
- Should be excluded from patching as they are test infrastructure
- Two harnesses contain known vulnerabilities (cpv_0, cpv_1) for benchmark purposes

### Test Exclusion Rationale
All files in `tests/` directory should be excluded from patching because:
1. They are test infrastructure, not production code
2. Modifying them could invalidate vulnerability detection
3. They include fuzzing harnesses with intentional vulnerabilities
4. Test data files should remain unchanged for reproducibility
5. Shell scripts are test orchestration, not functional code

### OSS-Fuzz Build Integration
- Build script: `.oss-fuzz/build.sh`
- Compiles fuzzing harnesses separately
- Links against libjq.a (static library)
- Includes Oniguruma library
- Generates seed corpus from .jq files
- Includes dictionary file: `.oss-fuzz/jq.dict`

## Recommendations for CRS

1. **Exclude all test files**: The comprehensive patch_exclude_list above should be used
2. **Focus on src/ directory**: Primary vulnerability locations in core library code
3. **Preserve test infrastructure**: Do not modify any files in tests/ directory
4. **Verify build system**: Ensure autotools files are excluded from patching
5. **Maintain OSS-Fuzz compatibility**: Do not modify .oss-fuzz/ directory contents

## References

- Main test suite: `tests/jq.test` (40KB, comprehensive functionality tests)
- Test framework: `src/jq_test.c` (14KB, unit test implementation)
- Test runner: Invoked via `jq --run-tests <file>` CLI option
- Build command: `make check` (runs all test scripts)
- OSS-Fuzz harnesses: 7 files in `tests/jq_fuzz_*.{c,cpp}`

---

**Analysis Date**: 2024
**Analyzer**: Claude (Anthropic)
**Project Version**: jq @ b8d58e2b26dc4c61c803f2bd4c13dac22d6213c0
