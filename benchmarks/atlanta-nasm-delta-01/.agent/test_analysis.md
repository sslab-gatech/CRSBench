# Test Analysis: NASM (atlanta-nasm-delta-01)

## Project Overview

**Project:** NASM (Netwide Assembler)
**Repository:** `/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766`
**Language:** C
**Build System:** Autoconf + Make
**Vulnerability:** Stack-use-after-return in preprocessor (CWE-562, CWE-825, CWE-416)

## Build System Analysis

### Primary Build System: Autoconf + GNU Make

**Configuration:**
- Build script: `./autogen.sh && ./configure && make`
- Main Makefile: `Makefile` (generated from `Makefile.in`)
- Build commands:
  - `make nasm` - builds main assembler
  - `make ndisasm` - builds disassembler
  - `make all` - builds all programs
  - `make rdf` - builds RDOFF utilities

**Key Build Locations:**
- `/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/Makefile`
- `/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/test/Makefile`
- `/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/rdoff/test/Makefile`

## Test Framework Analysis

### Test Framework: Custom Perl-based Test Harness

NASM uses a custom test framework built around Perl scripts that compare assembled output against golden reference files.

### Test Infrastructure Components

#### 1. Main Test Runner: `performtest.pl`
**Location:** `test/performtest.pl`

**Functionality:**
- Parses test directives embedded in assembly `.asm` files
- Runs NASM with specified arguments
- Compares output against golden reference files
- Supports three modes:
  - **test mode** (`make test`): Runs tests and compares against golden files
  - **golden mode** (`make golden`): Creates/updates golden reference files
  - **diff mode** (`make diff`): Shows differences between test outputs

**Test Directive Format:**
```asm
;Testname=<name>; Arguments=<nasm-args>; Files=<output-files>
```

Example from `test/float.asm`:
```asm
;Testname=unoptimized; Arguments=-O0 -fbin -ofloat.bin; Files=stdout stderr float.bin
;Testname=optimized;   Arguments=-Ox -fbin -ofloat.bin; Files=stdout stderr float.bin
```

#### 2. Travis CI Test Runner: `nasm-t.py`
**Location:** `travis/nasm-t.py`

**Functionality:**
- Python-based test runner for CI/CD
- Uses JSON test definitions in `travis/test/` directory
- Supports multiple output formats (bin, elf, obj, etc.)
- Compares binary outputs and stderr/stdout

#### 3. Bisection Helper: `bisect.sh`
**Location:** `test/bisect.sh`

**Purpose:** Used with `git bisect` to identify commits that introduced bugs

## Test File Organization

### Primary Test Directory: `test/`

**Contains:**
- **403 assembly test files** (`*.asm`)
- **5 C test files** for format-specific testing:
  - `aouttest.c` - a.out format tests
  - `elftest.c` - ELF32 shared library tests
  - `elftest64.c` - ELF64 shared library tests
  - `cofftest.c` - COFF format tests
  - `objlink.c` - OBJ format linking tests
- **6 Perl test scripts/generators**:
  - `performtest.pl` - main test runner
  - `iftoken.pl` - generates iftoken test
  - `riprel.pl` - generates RIP-relative addressing tests
  - `gas2nasm.py` - GAS to NASM converter
  - `perf/*.pl` - performance test generators

### Golden Reference Directory: `test/golden/`

**Purpose:** Contains expected output for all test cases
**Format:** Organized by test name, with subdirectories for each test case variant

### Test Results Directory: `test/testresults/`

**Purpose:** Stores actual test output for comparison against golden files

### Travis Test Directory: `travis/test/`

**Contains:**
- JSON test definitions (`.json` files)
- Expected binary outputs (`.bin.t`, `.o.t`, `.obj.t`)
- Expected stderr/stdout files (`.stderr`, `.stdout`)
- Assembly source files (`.asm`)

### RDOFF Test Directory: `rdoff/test/`

**Contains:**
- RDOFF format-specific tests
- 7 assembly test files
- Makefile for building RDOFF tests

## Test Categories

### 1. Unit Tests (Assembly Tests)

**Location:** `test/*.asm` (403 files)

**Categories:**

#### Instruction Set Tests
- `avx*.asm` - AVX/AVX2/AVX512 instruction tests
- `fpu.asm` - Floating-point unit tests
- `mpx*.asm` - Memory Protection Extensions
- `amx.asm` - Advanced Matrix Extensions
- `sha*.asm` - SHA instruction tests
- `crc32.asm` - CRC32 instruction tests
- `popcnt.asm` - POPCNT instruction tests

#### Floating-Point Tests
- `float*.asm` - Various floating-point format tests
- `hexfp.asm` - Hexadecimal floating-point tests
- `dtbcd.asm` - BCD (Binary Coded Decimal) tests

#### Addressing Mode Tests
- `riprel*.asm` - RIP-relative addressing (182KB test file)
- `addr64x.asm` - 64-bit addressing
- `a32offs.asm` - 32-bit offset tests
- `a64.asm` - 64-bit tests

#### Output Format Tests
- `bintest.asm` - Binary output format
- `cofftest.asm` - COFF format
- `elftest*.asm` - ELF format tests
- `objtest.asm` - OBJ format
- `aouttest.asm` - a.out format

#### Preprocessor Tests
- `ppindirect.asm` - Preprocessor indirect expansion
- `macro*.asm` - Macro expansion tests
- `ifmacro.asm` - Conditional macro tests
- `iftoken.asm` - Token conditional tests
- `emptyarg.asm` - Empty argument handling

#### Bug Regression Tests (br*)
Over 50 bug regression test files named `br*.asm`:
- `br1879590.asm` through `br3392708.asm`
- Each tests a specific bug fix
- Example: `br3392252.asm` tests TBM instruction encoding

#### Optimization Tests
- `optimization.asm` - General optimization tests
- `fwdopt*.asm` - Forward optimization tests
- `smartalign*.asm` - Smart alignment tests

#### Section/Segment Tests
- `multisection.asm` - Multiple section handling
- `subsection.asm` - Subsection tests
- `manysecs.asm`, `moresecs.asm`, `mostsecs.asm` - Section limit tests

#### Special Feature Tests
- `utf.asm` - UTF-8 handling
- `struc.asm` - Structure definitions
- `align*.asm` - Alignment directives
- `incbin.asm` - Binary inclusion
- `local.asm` - Local labels

### 2. Functional Tests (C Integration Tests)

**Purpose:** Test NASM's output when linked with C code

#### ELF Shared Library Tests
- `test/elftest.c` + `test/elfso.asm` - 32-bit ELF shared library
- `test/elftest64.c` + `test/elf64so.asm` - 64-bit ELF shared library
- Tests symbol resolution and calling conventions

#### COFF Tests
- `test/cofftest.c` + `test/cofftest.asm`
- Tests Windows COFF object format

#### a.out Tests
- `test/aouttest.c` + `test/aouttest.asm`
- Tests legacy a.out format

#### OBJ Linking Tests
- `test/objlink.c` + related assembly files
- Tests OMF object file format

### 3. Format-Specific Tests

#### RDOFF Tests
**Location:** `rdoff/test/`
- `rdftest*.asm` - RDOFF format tests
- `rdfseg*.asm` - RDOFF segment tests
- Tests NASM's Relocatable Dynamic Object File Format

### 4. Performance Tests

**Location:** `test/perf/`
- `label.pl` - Label performance tests
- `macro.pl` - Macro performance tests
- `token.pl` - Token processing performance tests

### 5. Travis CI Tests

**Location:** `travis/test/`
**Count:** 200+ JSON test definitions

Each test has:
- `.json` - Test configuration
- `.asm` - Assembly source
- `.bin.t` / `.o.t` / `.obj.t` - Expected binary output
- `.stderr` / `.stdout` - Expected error/output messages

## Test Execution Commands

### Via Root Makefile

```bash
# Run all tests
make test

# Create golden reference files
make golden

# Run Travis tests
make travis
```

**Command Details:**
```makefile
test: $(PROGS)
	cd test && $(RUNPERL) performtest.pl --nasm=../nasm *.asm

golden: $(PROGS)
	cd test && $(RUNPERL) performtest.pl --golden --nasm=../nasm *.asm

travis: $(PROGS)
	$(PYTHON3) travis/nasm-t.py run
```

### Via Test Directory

```bash
cd test

# Run all tests
perl performtest.pl --nasm=../nasm *.asm

# Run specific test
perl performtest.pl --nasm=../nasm float.asm

# Create golden files
perl performtest.pl --golden --nasm=../nasm *.asm

# Show differences
perl performtest.pl --diff --nasm=../nasm *.asm
```

### Via Travis Test Runner

```bash
# Run all travis tests
python3 travis/nasm-t.py run

# Run specific test
python3 travis/nasm-t.py run -t float

# List all tests
python3 travis/nasm-t.py list

# Update test references
python3 travis/nasm-t.py update
```

### Format-Specific Tests

```bash
cd test

# Test ELF32 shared library
make elftest

# Test ELF64 shared library
make elftest64

# RDOFF tests
cd rdoff/test
make all
```

## Patch Exclusion Strategy

### Critical Test Files to Exclude

Based on the vulnerability in `asm/preproc.c` (lines 891-908, 5373), patches should avoid modifying:

#### 1. Test Infrastructure Files
**Rationale:** These control test execution, not NASM functionality

```
test/performtest.pl
test/bisect.sh
test/iftoken.pl
test/riprel.pl
test/gas2nasm.py
test/perf/*.pl
test/Makefile
travis/nasm-t.py
rdoff/test/Makefile
```

#### 2. Golden Reference Files
**Rationale:** Expected outputs, not source code

```
test/golden/**/*
test/testresults/**/*
travis/test/*.bin.t
travis/test/*.o.t
travis/test/*.obj.t
travis/test/*.stderr
travis/test/*.stdout
```

#### 3. Test Data Files
**Rationale:** Input data for tests

```
test/incbin.data
test/br890790_i.asm
test/*.json (Travis test definitions)
```

#### 4. Documentation and Test C Files
**Rationale:** Test harnesses, not NASM implementation

```
test/*.c
test/README*
rdoff/test/*.c
```

#### 5. Build System Files (Test-Related)
**Rationale:** Test build configuration

```
test/Makefile.in
rdoff/test/Makefile
```

### Test Assembly Files - Context-Dependent

**General Principle:** Test `.asm` files should NOT be modified by patches UNLESS:
1. The patch adds a new feature requiring new tests
2. The patch fixes a bug that requires test output changes
3. The vulnerability is in preprocessor macro handling

**For this vulnerability (preprocessor stack-use-after-return):**

The vulnerability is in `asm/preproc.c`, specifically in:
- `dup_tlist()` function (lines 891-908)
- `expand_mmac_params()` function (line 5373)
- Related to TOKEN_INDIRECT handling and tokenize() zero-length tokens

**Test files LIKELY relevant to this vulnerability:**
```
test/ppindirect.asm     # Preprocessor indirect expansion
test/macro*.asm         # Macro expansion tests
test/emptyarg.asm       # Empty argument handling
test/ifmacro.asm        # Conditional macros
test/macro-defaults.asm # Macro default parameters
test/weirdpaste.asm     # Token pasting edge cases
test/xpaste.asm         # Paste operations
```

**However:** These test files should still be EXCLUDED from patches because:
1. They are test inputs, not implementation
2. Patches should fix the vulnerability in `asm/preproc.c`, not change test expectations
3. Only if the fix changes NASM behavior should test outputs (golden files) be updated

## Comprehensive Patch Exclude List

### File Patterns to Exclude

```gitignore
# Test runners and infrastructure
test/performtest.pl
test/bisect.sh
test/*.pl
test/*.py
test/Makefile
test/Makefile.in
travis/nasm-t.py
travis/*.py

# Test source files (assembly)
test/*.asm
travis/test/*.asm
rdoff/test/*.asm

# Test data files
test/*.data
test/*.inc
test/*.json

# Golden reference and results
test/golden/**
test/testresults/**
travis/test/*.bin.t
travis/test/*.o.t
travis/test/*.obj.t
travis/test/*.stderr
travis/test/*.stdout
travis/test/*.lst
travis/test/*.dep

# Test C files (harnesses)
test/*.c
test/*.h
rdoff/test/*.c

# Generated test files
test/*.bin
test/*.o
test/*.obj
test/*.exe
test/*.com
test/*.rdf
test/*.lst
test/*.i

# Performance test generators
test/perf/*.pl
test/perf/*.asm

# RDOFF test infrastructure
rdoff/test/Makefile
rdoff/test/*.sh

# Travis test definitions
travis/test/*.json

# Test documentation
test/README*
rdoff/test/README*
```

### Paths to Exclude (Absolute)

```
/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/test/
/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/rdoff/test/
/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/travis/test/
/home/acorn421/work/team-atlanta/afc-repos/cp-c-nasm-src-dc4e9766/travis/nasm-t.py
```

## Vulnerability-Specific Context

### Affected Files (Should be Patched)

**Primary:**
- `asm/preproc.c` - Contains the vulnerable `dup_tlist()` and `expand_mmac_params()` functions

**Potentially Related:**
- `asm/preproc.h` - Preprocessor interface definitions
- `asm/tokens.h` - Token definitions
- `asm/pptok.c` - Preprocessor token handling

### Test Files Related to Vulnerability

These files test preprocessor functionality but should still be EXCLUDED from patches:

```
test/ppindirect.asm         # Direct test of preprocessor indirection
test/macro-defaults.asm     # Macro parameter handling
test/emptyarg.asm           # Empty argument edge cases (2136 lines)
test/macro*.asm             # All macro-related tests
test/weirdpaste.asm         # Token pasting edge cases
test/xpaste.asm             # Cross-context pasting
test/ifmacro.asm            # Conditional macro expansion
test/evalmacro.asm          # Macro evaluation
test/exitrep.asm            # Macro repetition exit
```

**Why exclude?** These are regression tests. A proper fix should:
1. Modify ONLY `asm/preproc.c` (and possibly related implementation files)
2. NOT change test expectations unless the fix intentionally changes behavior
3. Ensure existing tests still pass with the fix applied

## Summary Statistics

| Category | Count | Location |
|----------|-------|----------|
| **Total Test Files** | 403 | `test/*.asm` |
| **Travis Test Defs** | 200+ | `travis/test/*.json` |
| **C Test Files** | 5 | `test/*.c` |
| **Perl Test Scripts** | 6 | `test/*.pl`, `test/perf/*.pl` |
| **Python Test Scripts** | 1 | `travis/nasm-t.py` |
| **RDOFF Tests** | 7 | `rdoff/test/*.asm` |
| **Bug Regression Tests** | 50+ | `test/br*.asm` |
| **Test Directories** | 3 | `test/`, `travis/test/`, `rdoff/test/` |

## Test Execution Matrix

| Test Command | Scope | Runtime | Purpose |
|--------------|-------|---------|---------|
| `make test` | All `.asm` in test/ | ~5-10 min | Full regression |
| `make golden` | All `.asm` in test/ | ~5-10 min | Update references |
| `make travis` | Travis test suite | ~2-5 min | CI/CD validation |
| `make elftest` | ELF32 shared lib | <1 min | Format-specific |
| `make elftest64` | ELF64 shared lib | <1 min | Format-specific |
| `perl performtest.pl <file>` | Single test | <1 sec | Individual test |

## Recommendations for Patch Generation CRS

### DO:
1. ✅ Modify implementation files in `asm/`, `disasm/`, `output/`, `nasmlib/`, etc.
2. ✅ Fix the vulnerability in `asm/preproc.c` (dup_tlist, expand_mmac_params)
3. ✅ Update function implementations to prevent stack-use-after-return
4. ✅ Add defensive checks for NULL or invalid pointers
5. ✅ Ensure tokenize() doesn't create zero-length tokens

### DON'T:
1. ❌ Modify any files in `test/` directory
2. ❌ Modify any files in `travis/test/` directory
3. ❌ Modify any files in `rdoff/test/` directory
4. ❌ Change test runner scripts (`performtest.pl`, `nasm-t.py`)
5. ❌ Update golden reference files
6. ❌ Modify test assembly files (`*.asm` in test directories)
7. ❌ Change test expectations or test data

### Verification Strategy:
1. Apply patch to `asm/preproc.c`
2. Rebuild NASM: `make clean && make nasm`
3. Run tests: `make test`
4. Verify all existing tests still pass
5. No test files should be modified by the patch

## Notes

- **Test Coverage:** NASM has extensive test coverage with 600+ test cases
- **Test Philosophy:** Tests are comprehensive regression tests ensuring output stability
- **Golden Files:** The golden/ directory contains known-good outputs; changes indicate behavior changes
- **Bug Tracking:** Tests are named after bug IDs (br*) for traceability
- **Format Support:** Tests cover all supported output formats (bin, elf, obj, coff, etc.)

## Conclusion

NASM uses a custom Perl-based test framework with extensive coverage. For patch generation:
- **Exclude ALL files under `test/`, `travis/test/`, and `rdoff/test/`**
- **Focus patches on implementation files, primarily `asm/preproc.c`**
- **Tests should pass unchanged after applying the vulnerability fix**
- **Only golden references might need updating if fix intentionally changes behavior**

This ensures patches fix the vulnerability without breaking the test infrastructure or creating false positives/negatives in test results.
