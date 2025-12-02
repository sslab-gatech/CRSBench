# Test Analysis for PCRE2 (atlanta-pcre2-full-01)

**Project Repository:** `/home/acorn421/work/team-atlanta/afc-repos/cp-c-pcre2-c13f2af8`
**Benchmark Directory:** `benchmarks/atlanta-pcre2-full-01`
**Analysis Date:** 2024

---

## 1. Build System and Test Framework

### Build System
- **Primary Build System:** GNU Autotools (Autoconf + Automake)
- **Alternative Build Systems:** CMake, Bazel (both supported but not primary)
- **Configuration Script:** `configure.ac` → `configure`
- **Build Definition:** `Makefile.am` → `Makefile.in` → `Makefile`

### Test Framework
- **Test Execution:** Automake test framework (`make check`)
- **Test Runner:** Custom shell scripts + compiled test binaries
- **Test Definition Location:** `Makefile.am` lines 225-228, 561-642

### Key Build Files
```
configure.ac          - Autoconf configuration
Makefile.am           - Automake build definition (907 lines)
CMakeLists.txt        - CMake build alternative (48,262 bytes)
BUILD.bazel           - Bazel build alternative
```

---

## 2. Unit Test Files and Components

### 2.1 Compiled Test Programs

#### A. POSIX Interface Test (`pcre2posix_test`)
**File:** `src/pcre2posix_test.c` (5,555 bytes)
- **Purpose:** Tests POSIX wrapper API (regex.h compatibility layer)
- **Build Target:** `noinst_PROGRAMS += pcre2posix_test`
- **Compilation:**
  - Source: `src/pcre2posix_test.c`
  - CFLAGS: `$(AM_CFLAGS) @PCRE2POSIX_CFLAG@`
  - Links: `libpcre2-posix.la libpcre2-8.la`
- **Execution:** Added to `TESTS +=` when `WITH_PCRE2_8` is enabled
- **Test Scope:**
  - Basic POSIX regex compilation
  - Pattern matching with various flags (REG_ICASE, REG_NEWLINE, REG_NOTBOL)
  - 5 test cases with different compiler and match flags
- **Exit Behavior:** Returns 0 on success, 1 on failure
- **Condition:** Only built when 8-bit library is enabled (`WITH_PCRE2_8`)

#### B. JIT Test (`pcre2_jit_test`)
**File:** `src/pcre2_jit_test.c` (108,190 bytes)
- **Purpose:** Tests Just-In-Time compilation features
- **Build Target:** `noinst_PROGRAMS += pcre2_jit_test`
- **Compilation:**
  - Source: `src/pcre2_jit_test.c`
  - CFLAGS: `$(AM_CFLAGS)`
  - Links: Conditionally links `libpcre2-8.la`, `libpcre2-16.la`, `libpcre2-32.la`
- **Execution:** Added to `TESTS +=` when `WITH_JIT` is enabled
- **Test Scope:**
  - JIT compiler correctness
  - Performance validation
  - Multi-width library support (8/16/32-bit)
- **Condition:** Only built when JIT support is enabled (`WITH_JIT`)

#### C. Main Test Program (`pcre2test`)
**File:** `src/pcre2test.c` (318,445 bytes)
- **Purpose:** Comprehensive test driver for all PCRE2 functionality
- **Build Target:** `bin_PROGRAMS += pcre2test` (installed binary)
- **Compilation:**
  - Source: `src/pcre2test.c`
  - Includes: `src/pcre2_printint.c` (via #include)
  - CFLAGS: `$(AM_CFLAGS)` + optional `$(VALGRIND_CFLAGS)` + `$(GCOV_CFLAGS)`
  - Links: `$(LIBREADLINE)` + width-specific libraries
- **Libraries Linked:**
  - 8-bit: `libpcre2-8.la libpcre2-posix.la`
  - 16-bit: `libpcre2-16.la`
  - 32-bit: `libpcre2-32.la`
- **Usage:** Used by `RunTest` script (see Section 2.2A)
- **Features:**
  - Pattern compilation testing
  - Match execution
  - DFA matching
  - UTF and UCP (Unicode properties) support
  - POSIX interface testing
  - Serialization/deserialization
  - JIT testing

### 2.2 Test Scripts

#### A. Main Test Script (`RunTest`)
**File:** `RunTest` (916 lines)
- **Type:** Bourne shell script
- **Execution:** Called via `TESTS += RunTest`
- **Purpose:** Orchestrates comprehensive PCRE2 library testing
- **Test Coverage:** 26 numbered tests + special tests
  - Test 0: Unchecked argument tests (coverage)
  - Test 1: Main non-UTF, non-UCP functionality
  - Test 2: API, errors, internals
  - Test 3: Locale-specific features
  - Test 4: UTF and Unicode property support
  - Test 5: API with UTF/UCP
  - Test 6: DFA matching (non-UTF)
  - Test 7: DFA matching with UTF
  - Test 8: Internal offsets and code size
  - Test 9: 8-bit library specials
  - Test 10: 8-bit UTF-8 and UCP specials
  - Test 11: 16/32-bit library specials
  - Test 12: 16/32-bit UTF and UCP specials
  - Test 13: 16/32-bit DFA specials
  - Test 14: DFA UTF/UCP specials
  - Test 15: Non-JIT limits
  - Test 16: JIT-specific (when JIT unavailable)
  - Test 17: JIT-specific (when JIT available)
  - Test 18: POSIX interface (no UTF/UCP)
  - Test 19: POSIX interface with UTF/UCP
  - Test 20: Serialization and code copy
  - Test 21: \C tests without UTF (DFA compatible)
  - Test 22: \C tests with UTF
  - Test 23: \C disabled test
  - Test 24: Non-UTF pattern conversion
  - Test 25: UTF pattern conversion
  - Test 26: Auto-generated unicode property tests
  - Special "heap" test: Environment-specific heap tests
- **Command-line Options:**
  - `-8`, `-16`, `-32`: Select library width
  - `-nojit`: Skip JIT tests
  - `-valgrind`: Run under Valgrind
  - `-valgrind-log`: Run under Valgrind with logging
  - `-sim <simulator>`: Run under simulator (cross-compilation)
  - `-bigstack`: Set large stack (for sanitizer builds)
  - `list`: List available tests
  - `ebcdic`: Run EBCDIC-specific test
  - Test numbers/ranges: e.g., `3-15 ~10` (run 3-15 except 10)
- **Test Data Files:** Uses `testdata/testinput[1-26]` with expected output in `testdata/testoutput*`
- **Execution Flow:**
  1. Detects available libraries (8/16/32-bit)
  2. Checks JIT support
  3. Runs selected tests with `pcre2test`
  4. Compares output against expected results
  5. Runs tests with and without JIT (when available)

#### B. Grep Test Script (`RunGrepTest`)
**File:** `RunGrepTest` (1,059 lines)
- **Type:** Bourne shell script
- **Execution:** Called via `TESTS += RunGrepTest` (when 8-bit library enabled)
- **Purpose:** Tests `pcre2grep` utility (file searching tool)
- **Dependencies:**
  - `pcre2grep` binary (must be executable)
  - `pcre2test` binary (for JIT detection)
- **Test Coverage:**
  - File handling and I/O
  - Command-line option processing
  - Pattern matching in files
  - Binary file handling
  - Compressed file support (gzip, bzip2)
  - Line number display
  - Context options (-A, -B, -C)
  - Recursive search
  - Unicode handling
  - Output formatting
- **Command-line Options:**
  - `valgrind`: Run tests under Valgrind
- **Test Data Files:** Uses `testdata/grep*` input/output files (23 files)
  - `grepinput*`: Test input files
  - `grepoutput*`: Expected output files
  - `grepbinary`: Binary file test
  - `greplist`: File list test
  - `grepinputC.gz`, `grepinputC.bz2`: Compressed file tests
- **Execution Method:**
  1. Runs in source directory (`$srcdir`)
  2. Executes multiple grep scenarios
  3. Compares output with expected results using `diff`
  4. Handles platform-specific differences (Solaris, MacOS, BSD)

#### C. Perl Compatibility Test (`perltest.sh`)
**File:** `perltest.sh` (402 lines)
- **Type:** Bourne shell script
- **Distribution:** `EXTRA_DIST += perltest.sh` (not in TESTS)
- **Purpose:** Compare PCRE2 behavior against Perl regex engine
- **Execution:** Manual (not part of `make check`)
- **Usage:**
  ```bash
  perltest.sh [-perl <perl_cmd>] [-w] [-utf8] [input_file] [output_file]
  ```
- **Supported Modifiers:**
  - `aftertext`: Print match suffix
  - `mark`: Show mark information
  - `no_start_optimize`: Disable start optimization
  - `subject_literal`: Don't process escapes in subjects
  - `ucp`: Enable Unicode properties (Perl /u)
  - `utf`: Enable UTF-8 mode
- **Test Input:** Uses `testinput1` and `testinput4` from testdata
- **Compatibility:** Tests Perl >= 5.10 compatibility
- **Note:** Not all PCRE2 test files are Perl-compatible

### 2.3 Fuzzing Support

#### Fuzzer Support Library
**File:** `src/pcre2_fuzzsupport.c`
- **Build:** `noinst_LIBRARIES = .libs/libpcre2-fuzzsupport.a` (when `WITH_FUZZ_SUPPORT`)
- **Purpose:** OSS-Fuzz integration library
- **Linked by:** OSS-Fuzz harnesses built in `.oss-fuzz/build.sh`

#### Fuzzer Check Program
**File:** Same source as fuzzsupport library
- **Build:** `noinst_PROGRAMS += pcre2fuzzcheck` (when `WITH_FUZZ_SUPPORT`)
- **Compilation:** `-DSTANDALONE` flag
- **Purpose:** Standalone fuzzer input checker
- **Links:** `libpcre2-8.la`

#### OSS-Fuzz Build Script
**File:** `.oss-fuzz/build.sh` (51 lines)
- **Purpose:** Build fuzzer harnesses for OSS-Fuzz
- **Configuration:**
  - `--enable-fuzz-support`
  - `--enable-never-backslash-C`
  - `--with-match-limit=1000`
  - `--with-match-limit-depth=1000`
  - `--enable-jit`
- **Fuzzer Targets:**
  - `pcre2_fuzzer` (default link size)
  - `pcre2_fuzzer_3l` (link size 3)
  - `pcre2_fuzzer_4l` (link size 4)
- **Fuzzer Dictionaries:** `testdata/fuzzing/pcre2_fuzzer*.dict`

### 2.4 Test Data Files

#### Main Test Data
**Location:** `testdata/`
- **Input Files:** 28 test input files
  - `testinput1` through `testinput26`
  - `testinputEBC` (EBCDIC test)
  - `testinputheap` (heap test)
- **Output Files:** 46 expected output files
  - `testoutput[1-26]` with various width/mode variants
  - Format: `testoutput<N>[-<width>][-<variant>]`
  - Examples: `testoutput8-16-2`, `testoutput11-32`, `testoutputheap-8`
- **Special Files:**
  - `testbtables`: Binary character tables
  - `wintestinput3`, `wintestoutput3`: Windows-specific tests
  - `valgrind-jit.supp`: Valgrind suppressions for JIT

#### Grep Test Data
**Location:** `testdata/`
- **Count:** 23 grep-related files
- **Input Files:**
  - `grepinput`, `grepinput3`, `grepinput8`
  - `grepinputC.gz`, `grepinputC.bz2` (compressed)
  - `grepinputM`, `grepinputv`, `grepinputx`
  - `grepbinary`: Binary file test
- **Output Files:**
  - `grepoutput`, `grepoutput8`, `grepoutputC`
  - `grepoutputN`, `grepoutputUN`, `grepoutputCN`, etc.
  - Various format variants (numbered, with context, compressed)
- **Auxiliary Files:**
  - `greplist`: File list for testing
  - `grepfilelist`: File list input
  - `greppatN4`: Pattern file

#### Fuzzing Test Data
**Location:** `testdata/fuzzing/`
- **Files:** 6 files
  - `pcre2_fuzzer.dict`, `pcre2_fuzzer.options` (8-bit)
  - `pcre2_fuzzer_16.dict`, `pcre2_fuzzer_16.options` (16-bit)
  - `pcre2_fuzzer_32.dict`, `pcre2_fuzzer_32.options` (32-bit)

### 2.5 Demo and Helper Programs

#### Demo Program
**File:** `src/pcre2demo.c` (16,034 bytes per NEWS)
- **Distribution:** `EXTRA_DIST += src/pcre2demo.c`
- **Purpose:** Example code for PCRE2 usage
- **Build:** Not built automatically (users build manually)

#### Character Tables Generator
**File:** `src/pcre2_dftables.c`
- **Build:** `noinst_PROGRAMS += pcre2_dftables` (when `WITH_REBUILD_CHARTABLES`)
- **Purpose:** Generate character classification tables
- **Output:** `src/pcre2_chartables.c`
- **Default:** Uses distributed `src/pcre2_chartables.c.dist` (ASCII)

#### Grep Utility
**File:** `src/pcre2grep.c`
- **Build:** `bin_PROGRAMS += pcre2grep` (installed, when 8-bit library enabled)
- **Purpose:** grep-like utility using PCRE2
- **Links:** `libpcre2-8.la` + `$(LIBZ)` + `$(LIBBZ2)`

---

## 3. Test Commands and Execution

### 3.1 Standard Test Execution

#### Run All Tests
```bash
make check
```
**Tests Run:**
- `pcre2posix_test` (if 8-bit library enabled)
- `pcre2_jit_test` (if JIT enabled)
- `RunTest` (main test suite)
- `RunGrepTest` (if 8-bit library enabled)

#### Run Specific Test Components
```bash
# Run only POSIX tests
./pcre2posix_test

# Run only JIT tests
./pcre2_jit_test

# Run specific numbered tests
./RunTest 1-5           # Run tests 1 through 5
./RunTest 10            # Run only test 10
./RunTest 3-15 ~10      # Run 3-15 except 10
./RunTest ~10           # Run all tests except 10

# Run tests without JIT
./RunTest -nojit

# Run specific library width
./RunTest -8            # 8-bit library only
./RunTest -16           # 16-bit library only
./RunTest -32           # 32-bit library only

# List available tests
./RunTest list

# Run special tests
./RunTest heap          # Heap test
./RunTest ebcdic        # EBCDIC test

# Run with Valgrind
./RunTest -valgrind
./RunTest -valgrind-log

# Run grep tests
./RunGrepTest
./RunGrepTest valgrind
```

### 3.2 Test Build Dependencies

#### Configuration Required
Tests require proper configuration:
```bash
./autogen.sh
./configure [options]
make
make check
```

#### Common Configure Options
```bash
# Enable JIT for JIT tests
--enable-jit

# Enable different library widths
--enable-pcre2-8        # 8-bit (default)
--enable-pcre2-16       # 16-bit
--enable-pcre2-32       # 32-bit

# Enable fuzzing support
--enable-fuzz-support

# Enable code coverage
--enable-coverage

# Enable Valgrind support
--enable-valgrind
```

### 3.3 Coverage Testing

#### Build with Coverage
```bash
./configure --enable-coverage
make
make coverage           # Run tests and generate coverage report
```

#### Coverage Targets
- `coverage`: Complete coverage analysis
- `coverage-baseline`: Capture baseline coverage
- `coverage-check`: Run tests for coverage
- `coverage-report`: Generate HTML report
- `coverage-reset`: Zero coverage counters
- `coverage-clean`: Remove coverage data and reports

**Output:** HTML report in `$(PACKAGE)-$(VERSION)-coverage/index.html`

---

## 4. Test File Categories and Exclusions

### 4.1 Test-Specific Source Files

Files that should be **excluded from patches** as they are test infrastructure:

#### Test Programs (3 files)
```
src/pcre2posix_test.c      - POSIX wrapper test program
src/pcre2_jit_test.c       - JIT compiler test program
src/pcre2test.c            - Main test driver program
```

#### Test Helper/Support (3 files)
```
src/pcre2_fuzzsupport.c    - Fuzzing support library
src/pcre2_printint.c       - Print internal structures (included by pcre2test)
src/pcre2demo.c            - Demo/example program
```

#### Utilities (Not Core Library) (2 files)
```
src/pcre2grep.c            - Grep utility (uses library, not part of library)
src/pcre2_dftables.c       - Character table generator (build-time only)
```

#### Test Scripts (3 files)
```
RunTest                     - Main test orchestration script
RunGrepTest                 - Grep utility test script
perltest.sh                 - Perl compatibility test script
```

#### Maintenance Scripts (7 files)
```
autogen.sh                  - Autotools bootstrapping
PrepareRelease              - Release preparation
CheckMan                    - Man page checker
CleanTxt                    - Text file cleaner
Detrail                     - Trailing whitespace remover
132html                     - HTML formatter
pcre2-config.in             - Config script template
```

### 4.2 Test Data Files

All files under `testdata/` directory should be excluded from patches:

#### Main Test Data (74 files)
```
testdata/testinput[1-26]                    - Test input data (28 files)
testdata/testoutput*                        - Expected outputs (46 files)
testdata/testinputEBC                       - EBCDIC input
testdata/testinputheap                      - Heap test input
testdata/wintestinput3, wintestoutput3      - Windows-specific
testdata/testbtables                        - Binary tables
testdata/valgrind-jit.supp                  - Valgrind suppressions
```

#### Grep Test Data (23 files)
```
testdata/grep*                              - All grep test files
```

#### Fuzzing Data (6 files)
```
testdata/fuzzing/*.dict                     - Fuzzer dictionaries
testdata/fuzzing/*.options                  - Fuzzer options
```

### 4.3 Build System Files

Configuration and build files (generally excluded):

#### Autotools Generated (exclude from patches)
```
aclocal.m4                  - Autoconf macros (generated)
configure                   - Configure script (generated from configure.ac)
Makefile.in                 - Makefile template (generated from Makefile.am)
Makefile                    - Generated Makefile
config.guess, config.sub    - Platform detection
compile, depcomp            - Compilation helpers
install-sh, missing         - Installation helpers
ar-lib, test-driver         - Build helpers
ltmain.sh, libtool          - Libtool
*.log, *.trs                - Test logs
```

#### Autotools Source (keep, but not patch targets)
```
configure.ac                - Autoconf source
Makefile.am                 - Automake source
```

#### Alternative Build Systems
```
CMakeLists.txt              - CMake configuration
BUILD.bazel                 - Bazel build file
build.zig                   - Zig build file
MODULE.bazel                - Bazel module
WORKSPACE.bazel             - Bazel workspace
.bazelrc                    - Bazel config
```

### 4.4 Library Source Files (PATCH TARGETS)

These are the **actual library implementation** files that should be **included in patches**:

#### Core Library Sources (23 files in COMMON_SOURCES)
```
src/pcre2_auto_possess.c        - Auto-possessification optimization
src/pcre2_chkdint.c             - Check integer
src/pcre2_compile.c             - Pattern compilation
src/pcre2_config.c              - Configuration queries
src/pcre2_context.c             - Context management
src/pcre2_convert.c             - Pattern conversion (glob, POSIX)
src/pcre2_dfa_match.c           - DFA matching algorithm
src/pcre2_error.c               - Error handling
src/pcre2_extuni.c              - Extended Unicode
src/pcre2_find_bracket.c        - Bracket finding
src/pcre2_jit_compile.c         - JIT compilation
src/pcre2_maketables.c          - Character table creation
src/pcre2_match.c               - Main matching algorithm
src/pcre2_match_data.c          - Match data management
src/pcre2_newline.c             - Newline handling
src/pcre2_ord2utf.c             - Ordinal to UTF conversion
src/pcre2_pattern_info.c        - Pattern information
src/pcre2_script_run.c          - Script run support
src/pcre2_serialize.c           - Serialization
src/pcre2_string_utils.c        - String utilities
src/pcre2_study.c               - Pattern study/optimization
src/pcre2_substitute.c          - Substitution
src/pcre2_substring.c           - Substring extraction
src/pcre2_tables.c              - Character tables
src/pcre2_ucd.c                 - Unicode character data
src/pcre2_valid_utf.c           - UTF validation
src/pcre2_xclass.c              - Extended character classes
```

#### POSIX Wrapper
```
src/pcre2posix.c                - POSIX regex API wrapper
```

#### JIT Support Files (included by pcre2_jit_compile.c)
```
src/pcre2_jit_match.c           - JIT match execution
src/pcre2_jit_misc.c            - JIT miscellaneous
```

#### Supporting Data Files
```
src/pcre2_ucptables.c           - Unicode property tables (included by pcre2_tables.c)
```

#### SLJIT (JIT Backend) - 34 Files
All files under `src/sljit/` are part of the JIT implementation:
```
src/sljit/sljitLir.c            - Lightweight JIT IR
src/sljit/sljitUtils.c          - JIT utilities
src/sljit/sljitNative*.c        - Platform-specific JIT (ARM, x86, MIPS, PPC, RISC-V, S390X)
src/sljit/allocator_src/*.c     - Memory allocators (10 files)
```

#### Header Files
```
src/pcre2.h.in                  - Main header template
src/pcre2.h.generic             - Generic header
src/pcre2posix.h                - POSIX wrapper header
src/pcre2_internal.h            - Internal definitions
src/pcre2_intmodedep.h          - Internal mode-dependent
src/pcre2_ucp.h                 - Unicode properties
src/pcre2_jit_neon_inc.h        - JIT NEON support
src/pcre2_jit_simd_inc.h        - JIT SIMD support
src/sljit/*.h                   - JIT backend headers
```

### 4.5 Documentation (Exclude from Patches)

```
README, README.md               - Project readme
AUTHORS                         - Author list
COPYING, LICENCE                - License files
ChangeLog, NEWS                 - Change history
HACKING                         - Developer guide
NON-AUTOTOOLS-BUILD            - Build guide
index.md                        - Documentation index
doc/**                          - All documentation
```

---

## 5. Comprehensive Patch Exclude List

### 5.1 Complete Exclusion Patterns

For patch generation/validation, **EXCLUDE** these patterns:

```
# Test Programs and Test Infrastructure
src/pcre2posix_test.c
src/pcre2_jit_test.c
src/pcre2test.c
src/pcre2_fuzzsupport.c
src/pcre2_printint.c
src/pcre2demo.c

# Utilities (not library code)
src/pcre2grep.c
src/pcre2_dftables.c

# Test Scripts
RunTest
RunTest.bat
RunGrepTest
RunGrepTest.bat
perltest.sh

# All Test Data
testdata/**

# Build/Maintenance Scripts
autogen.sh
PrepareRelease
CheckMan
CleanTxt
Detrail
132html
pcre2-config.in
pcre2-config

# Generated Files (from Autotools)
aclocal.m4
configure
Makefile.in
Makefile
config.guess
config.sub
config.log
config.status
compile
depcomp
install-sh
missing
ar-lib
test-driver
ltmain.sh
libtool
*.log
*.trs
*.o
*.la
*.lo
.libs/**
.deps/**

# Alternative Build Systems
CMakeLists.txt
BUILD.bazel
build.zig
MODULE.bazel
WORKSPACE.bazel
.bazelrc
cmake/**

# pkg-config files
*.pc
*.pc.in

# Documentation
README
README.md
AUTHORS
COPYING
LICENCE
ChangeLog
NEWS
HACKING
NON-AUTOTOOLS-BUILD
index.md
doc/**
maint/**

# Git/Version Control
.git/**
.github/**
.gitignore

# OSS-Fuzz Integration
.oss-fuzz/**

# Temporary/Generated Test Files
testSinput
test3input
test3output
test3outputA
test3outputB
testtry
teststdout
teststderr
teststderrgrep
testtemp1grep
testtemp2grep
testtrygrep
testNinputgrep
```

### 5.2 Files to INCLUDE in Patches

Only these patterns should be **INCLUDED** in vulnerability patches:

```
# Core Library Implementation
src/pcre2_auto_possess.c
src/pcre2_chkdint.c
src/pcre2_compile.c
src/pcre2_config.c
src/pcre2_context.c
src/pcre2_convert.c
src/pcre2_dfa_match.c
src/pcre2_error.c
src/pcre2_extuni.c
src/pcre2_find_bracket.c
src/pcre2_jit_compile.c
src/pcre2_jit_match.c
src/pcre2_jit_misc.c
src/pcre2_maketables.c
src/pcre2_match.c
src/pcre2_match_data.c
src/pcre2_newline.c
src/pcre2_ord2utf.c
src/pcre2_pattern_info.c
src/pcre2_script_run.c
src/pcre2_serialize.c
src/pcre2_string_utils.c
src/pcre2_study.c
src/pcre2_substitute.c
src/pcre2_substring.c
src/pcre2_tables.c
src/pcre2_ucd.c
src/pcre2_ucptables.c
src/pcre2_valid_utf.c
src/pcre2_xclass.c
src/pcre2posix.c

# JIT Backend (SLJIT)
src/sljit/**/*.c
src/sljit/**/*.h

# Library Headers
src/pcre2.h.in
src/pcre2.h.generic
src/pcre2posix.h
src/pcre2_internal.h
src/pcre2_intmodedep.h
src/pcre2_ucp.h
src/pcre2_jit_neon_inc.h
src/pcre2_jit_simd_inc.h

# Character Tables (if modified)
src/pcre2_chartables.c.dist
```

---

## 6. Test Execution Summary

### 6.1 Automated Tests (via `make check`)

| Test Component | File | Condition | Description |
|----------------|------|-----------|-------------|
| POSIX Test | `pcre2posix_test` | `WITH_PCRE2_8` | POSIX API wrapper tests |
| JIT Test | `pcre2_jit_test` | `WITH_JIT` | JIT compiler tests |
| Main Test Suite | `RunTest` | Always | 26 comprehensive tests |
| Grep Tests | `RunGrepTest` | `WITH_PCRE2_8` | pcre2grep utility tests |

### 6.2 Manual/Optional Tests

| Test Component | File | Purpose |
|----------------|------|---------|
| Perl Compatibility | `perltest.sh` | Compare with Perl regex engine |
| Fuzzing | `pcre2fuzzcheck` | Standalone fuzzer checker |
| Demo | `pcre2demo.c` | Example usage (user builds) |
| Coverage | `make coverage` | Code coverage analysis |
| Valgrind | `RunTest -valgrind` | Memory leak detection |

### 6.3 Test Data Statistics

- **Main Test Inputs:** 28 files (testinput1-26 + EBC + heap)
- **Main Test Outputs:** 46 expected output files
- **Grep Test Files:** 23 files (inputs + outputs)
- **Fuzzing Files:** 6 files (dictionaries + options)
- **Total Test Data Files:** ~103 files

---

## 7. Key Findings for Patch Validation

### 7.1 Critical Library Files (Must Review)
1. **Pattern Compilation:** `pcre2_compile.c` (most complex, 11K+ lines likely)
2. **Matching Engines:** `pcre2_match.c`, `pcre2_dfa_match.c`
3. **JIT Compiler:** `pcre2_jit_compile.c`, JIT backend files
4. **UTF/Unicode:** `pcre2_valid_utf.c`, `pcre2_ucd.c`, `pcre2_extuni.c`
5. **Memory Management:** `pcre2_context.c`, `pcre2_match_data.c`

### 7.2 Common Vulnerability Areas
Based on test coverage:
- UTF validation and edge cases
- Integer overflow in pattern compilation
- Buffer overflows in matching
- JIT compiler code generation bugs
- Unicode property handling
- Recursion/stack depth limits
- Character class handling

### 7.3 Test-Driven Validation Strategy
1. **Identify vulnerability type** from CVE/advisory
2. **Map to relevant test suite**:
   - UTF bugs → Tests 4, 5, 7, 10, 12, 19, 22, 25
   - DFA bugs → Tests 6, 7, 13, 14
   - JIT bugs → Tests 16, 17
   - POSIX bugs → Tests 18, 19
   - Parsing bugs → Tests 1, 2, 24, 26
3. **Run targeted tests** before/after patch
4. **Verify no regressions** with full `make check`

### 7.4 Test Files That Exercise Vulnerability Classes

| Vulnerability Class | Relevant Tests | Test Files |
|---------------------|----------------|------------|
| Buffer Overflow | Tests 1-2, 4-5 | testinput1, testinput2, testinput4, testinput5 |
| UTF Validation | Tests 4, 5, 7, 10, 12 | testinput4, testinput5, testinput7, testinput10, testinput12 |
| Integer Overflow | Test 2, 8 | testinput2, testinput8 |
| Regex DoS / ReDoS | Test 15 | testinput15 |
| JIT Bugs | Tests 16-17 | testinput16, testinput17 |
| Unicode Property | Tests 4-5, 26 | testinput4, testinput5, testinput26 |
| DFA Matching | Tests 6-7, 13-14 | testinput6, testinput7, testinput13, testinput14 |
| POSIX Interface | Tests 18-19 | testinput18, testinput19, pcre2posix_test.c |
| Serialization | Test 20 | testinput20 |
| Backslash-C | Tests 21-23 | testinput21, testinput22, testinput23 |

---

## 8. Recommendations

### 8.1 For Automated Patch Validation
1. **Always run:** `make check` after applying any patch
2. **Check logs:** Review `test-suite.log` for failures
3. **Targeted testing:** Run specific tests related to patched code area
4. **Regression detection:** Compare test results before/after patch

### 8.2 For Patch Generation
1. **Exclude all test files** from patches (see Section 5.1)
2. **Include only library sources** (see Section 5.2)
3. **Preserve test compatibility:** Patches should not break existing tests
4. **Document test impact:** Note which tests exercise the patched code

### 8.3 For CRS Integration
1. **Pre-patching validation:** Run tests on original code
2. **Post-patching validation:** Run tests after applying patch
3. **Diff comparison:** Compare test outputs to detect unintended changes
4. **Coverage analysis:** Use `make coverage` to verify patch reaches vulnerable code

---

## Appendices

### A. Test Execution Environment

**Required Environment Variables:**
- `srcdir`: Source directory (auto-set by `make check`)
- `builddir`: Build directory (auto-detected)

**Optional Environment Variables:**
- `VALGRIND`: Path to valgrind
- `PCRE2GREP_COLOUR`, `GREP_COLORS`: Color settings (unset by tests)

### B. Cross-References

**Build System Documentation:**
- `NON-AUTOTOOLS-BUILD`: Alternative build instructions
- `HACKING`: Developer guide

**Test Documentation:**
- Comments in `RunTest`: Test descriptions
- Comments in `RunGrepTest`: Grep test descriptions
- `doc/pcre2test.txt`: pcre2test program documentation

### C. File Statistics

| Category | Count | Notes |
|----------|-------|-------|
| Library .c files | 28 core + 6 JIT + 34 SLJIT = 68 | Patch targets |
| Test programs | 3 | pcre2test, pcre2_jit_test, pcre2posix_test |
| Test scripts | 3 | RunTest, RunGrepTest, perltest.sh |
| Test input files | 28 | testinput[1-26] + EBC + heap |
| Test output files | 46 | Various width/mode combinations |
| Grep test files | 23 | Input/output pairs |
| Fuzzing files | 6 | Dictionaries and options |
| Utilities | 2 | pcre2grep, pcre2_dftables |
| Demo/Support | 3 | pcre2demo, pcre2_fuzzsupport, pcre2_printint |

**Total Lines of Test Code:**
- `RunTest`: 916 lines
- `RunGrepTest`: 1,059 lines
- `perltest.sh`: 402 lines
- `pcre2test.c`: ~318,445 bytes (~10,000 lines estimated)
- `pcre2_jit_test.c`: ~108,190 bytes (~3,500 lines estimated)
- **Total:** ~15,000+ lines of test infrastructure

---

## Conclusion

PCRE2 has a comprehensive, multi-layered test infrastructure:

1. **Unit Tests:** Direct testing via compiled programs (POSIX, JIT)
2. **Functional Tests:** Comprehensive test suite (26 numbered tests)
3. **Integration Tests:** pcre2grep utility testing
4. **Compatibility Tests:** Perl comparison testing
5. **Fuzz Testing:** OSS-Fuzz integration
6. **Coverage Testing:** gcov/lcov integration

**For patch validation:**
- **Exclude:** All test infrastructure, test data, documentation, build system
- **Include:** Only `src/` library implementation files and headers
- **Validate:** Run `make check` and verify no regressions
- **Target:** Focus testing on vulnerability-related code areas

This analysis provides a complete foundation for automated patch generation, validation, and test-driven vulnerability remediation in the atlanta-pcre2-full-01 benchmark.
