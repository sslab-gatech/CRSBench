# Test Analysis for tmux (atlanta-tmux-delta-01)

## Project Information

- **Project**: tmux
- **Repository**: `/mnt/ssd1/acorn421/team-atlanta/repos/cp-c-tmux-0e2a8078`
- **Benchmark**: atlanta-tmux-delta-01
- **Language**: C
- **Build System**: GNU Autotools (Automake/Autoconf)
- **Test Framework**: Shell-based regression tests

## Build System Analysis

### Primary Build Files

1. **configure.ac** - Autoconf configuration
   - Lines: 930
   - Defines build options, platform detection, library checks
   - Fuzzing support via `--enable-fuzzing` flag (line 25-42)
   - Conditional compilation for fuzzers (line 98)

2. **Makefile.am** - Automake configuration
   - Lines: 237
   - Main executable: `tmux`
   - Fuzzer target: `fuzz/input-fuzzer` (lines 219-223)
   - Test command: `make check` (triggers fuzzer build)

3. **build.sh** (.oss-fuzz/build.sh)
   - OSS-Fuzz build script
   - Enables fuzzing via `--enable-fuzzing` flag
   - Runs `make -j"$(nproc)" check` (line 28)
   - Copies fuzzer binaries, options, and dictionaries to $OUT

### Build Process

```bash
./autogen.sh
./configure --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "
make -j"$(nproc)" check
```

## Test Framework Analysis

### Test Type: Regression Tests

tmux uses **shell-based regression tests** located in the `regress/` directory.

### Test Directory Structure

```
regress/
├── Makefile                    # Test runner
├── *.sh (26 test scripts)      # Functional test scripts
├── *.result (4 result files)   # Expected output files
├── *.txt (2 test data files)   # Test input data
└── conf/ (21 config files)     # Test configurations
```

### Test Runner

**File**: `regress/Makefile`

```makefile
TESTS!= echo *.sh

.PHONY: all $(TESTS)
.NOTPARALLEL: all $(TESTS)

all: $(TESTS)

$(TESTS):
	sh $*.sh
	sleep 1
```

### Test Command

```bash
cd regress
make all
# Or run individual tests:
sh cursor-test1.sh
```

### Test Inventory

#### Functional Test Scripts (26 total)

1. **Cursor Tests** (4 tests)
   - `cursor-test1.sh` - Window resizing with cursor tracking
   - `cursor-test2.sh` - Cursor positioning test
   - `cursor-test3.sh` - Cursor behavior test
   - `cursor-test4.sh` - Advanced cursor test

2. **Copy Mode Tests** (2 tests)
   - `copy-mode-test-emacs.sh` - Emacs-style copy mode (116 lines)
   - `copy-mode-test-vi.sh` - Vi-style copy mode (115 lines)

3. **Session Management Tests** (5 tests)
   - `new-session-base-index.sh` - Base index configuration
   - `new-session-command.sh` - Session creation with commands
   - `new-session-environment.sh` - Environment variable handling (66 lines)
   - `new-session-no-client.sh` - Detached session creation
   - `new-session-size.sh` - Session size configuration
   - `has-session-return.sh` - Session existence checking

4. **Window Management Tests** (2 tests)
   - `new-window-command.sh` - Window creation
   - `kill-session-process-exit.sh` - Session cleanup

5. **Control Mode Tests** (2 tests)
   - `control-client-sanity.sh` - Control client basic operations (42 lines)
   - `control-client-size.sh` - Control client sizing (49 lines)

6. **Format String Tests** (1 test)
   - `format-strings.sh` - Format substitution testing (182 lines, comprehensive)

7. **Configuration Tests** (2 tests)
   - `conf-syntax.sh` - Configuration file parsing
   - `command-order.sh` - Command execution order (51 lines)

8. **Conditional Tests** (3 tests)
   - `if-shell-error.sh` - Error handling in if-shell
   - `if-shell-nested.sh` - Nested if-shell commands
   - `if-shell-TERM.sh` - TERM variable in if-shell (30 lines)

9. **Display Tests** (4 tests)
   - `capture-pane-sgr0.sh` - SGR0 attribute capturing (31 lines)
   - `am-terminal.sh` - Auto-margin terminal behavior (29 lines)
   - `osc-11colours.sh` - OSC color sequence handling (244 lines)
   - `style-trim.sh` - Style attribute trimming (91 lines)

#### Test Data Files

1. **Input Data**
   - `cursor-test.txt` - Cursor test input data
   - `copy-mode-test.txt` - Copy mode test data

2. **Expected Results**
   - `cursor-test1.result` - Expected output for cursor-test1
   - `cursor-test2.result` - Expected output for cursor-test2
   - `cursor-test3.result` - Expected output for cursor-test3
   - `cursor-test4.result` - Expected output for cursor-test4

3. **Configuration Files**
   - `conf/*.conf` - 21 configuration files (MD5-named)

### Test Pattern

All test scripts follow a common pattern:

```bash
#!/bin/sh

PATH=/bin:/usr/bin
TERM=screen

[ -z "$TEST_TMUX" ] && TEST_TMUX=$(readlink -f ../tmux)
TMUX="$TEST_TMUX -f/dev/null -Ltest"
$TMUX kill-server 2>/dev/null

# Test-specific commands
$TMUX new -d "commands..."
$TMUX display -pF '#{format_string}'

# Verify results
cmp -s $TMP expected.result || exit 1

$TMUX kill-server 2>/dev/null
exit 0
```

## Fuzzing Infrastructure

### Fuzzer Files

1. **fuzz/input-fuzzer.c** (97 lines)
   - LibFuzzer harness for input parsing
   - Entry point: `LLVMFuzzerTestOneInput()`
   - Initializer: `LLVMFuzzerInitialize()`
   - Tests: Terminal input sequence parsing
   - Maximum input length: 512 bytes (FUZZER_MAXLEN)
   - Pane dimensions: 80x25

2. **fuzz/input-fuzzer.dict** (66 bytes)
   - Dictionary for fuzzing efficiency

3. **fuzz/input-fuzzer.options** (26 bytes)
   - Fuzzer runtime options

### Fuzzer Build Configuration

From `Makefile.am` (lines 219-223):

```makefile
if NEED_FUZZING
check_PROGRAMS = fuzz/input-fuzzer
fuzz_input_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_input_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
endif
```

### Fuzzer Purpose

The `input-fuzzer` tests:
- Terminal input sequence parsing (`input_parse_buffer()`)
- Window pane input handling
- Command queue processing (`cmdq_next()`)
- Event loop handling (libevent)

## Test-Related Source Files

While there are no dedicated unit test files, these source files contain test-related functionality:

1. **Production code with "test" in comments** (12 files):
   - `tty.c` - TTY handling
   - `tty-acs.c` - ACS character handling
   - `resize.c` - Window resizing
   - `screen-write.c` - Screen writing operations
   - `server-client.c` - Client-server communication
   - `spawn.c` - Process spawning
   - `options-table.c` - Options table
   - `format.c` - Format string handling
   - `input.c` - Input processing
   - `cmd-new-window.c` - New window command
   - `cmd-select-window.c` - Window selection command
   - `cmd-break-pane.c` - Pane breaking command

2. **Compatibility headers**:
   - `compat/bitstring.h` - Contains "test" in macro definitions

## Test Exclusions for Patching

### Current Exclusion List (from meta.yaml)

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

### Comprehensive Test Exclusion List

Based on this analysis, the following files should be excluded from patching:

#### Test Infrastructure
```yaml
# Regression test directory (entire directory)
- regress/**

# Fuzzer harness (test code, not production)
- fuzz/input-fuzzer.c
- fuzz/input-fuzzer.dict
- fuzz/input-fuzzer.options
- fuzz/**
```

#### Build System (already covered)
```yaml
- build.sh
- Makefile
- Makefile.am
- configure
- configure.ac
- autogen.sh
- '*.am'
- '*.ac'
```

#### Documentation (already covered)
```yaml
- '*.md'
- README*
- CHANGES
- COPYING
- SYNCING
- docs/**
```

#### Project Metadata (already covered)
```yaml
- .aixcc/**
- .oss-fuzz/**
- .gitignore
- .mailmap
- .travis.yml
- .github/**
```

#### Tools and Presentation
```yaml
- tools/**
- presentations/**
- logo/**
- mdoc2man.awk
```

#### Example Configurations
```yaml
- example_tmux.conf
```

### Updated Complete Exclusion List

```yaml
patch_exclude_list:
# Build system
- build.sh
- Makefile
- Makefile.am
- CMakeLists.txt
- configure
- configure.ac
- autogen.sh
- '*.ac'
- '*.am'

# Test infrastructure
- regress/**
- fuzz/**
- test/**
- tests/**
- '**/*test*.c'
- '**/*test*.cc'
- '**/*test*.cpp'
- '**/*test*.h'

# Documentation
- docs/**
- '*.md'
- README*
- CHANGES
- COPYING
- SYNCING

# Project metadata
- .aixcc/**
- .oss-fuzz/**
- .gitignore
- .git/**
- .github/**
- .mailmap
- .travis.yml

# Tools and utilities
- tools/**
- presentations/**
- logo/**
- mdoc2man.awk

# Examples
- example_tmux.conf
```

## Vulnerability Information

From `meta.yaml`:

### Harness
- **Name**: input-fuzzer
- **Path**: $REPO/fuzz/input-fuzzer.c

### Vulnerabilities

1. **cpv_0**
   - POV ID: pov_0
   - Sanitizer: AddressSanitizer
   - Error: Stack buffer overflow
   - Token: `ERROR: AddressSanitizer: stack-buffer-overflow`

2. **cpv_1**
   - POV ID: pov_0
   - Sanitizer: AddressSanitizer
   - Error: Heap buffer overflow
   - Token: `ERROR: AddressSanitizer: heap-buffer-overflow`

## Summary

### Test Framework: Shell-based Regression Tests

- **Total Test Files**: 54
- **Test Scripts**: 26 shell scripts
- **Test Data**: 2 input files, 4 result files, 21 config files
- **Test Runner**: `regress/Makefile`
- **Test Command**: `make all` (in regress directory)

### Fuzzing Infrastructure

- **Fuzzer**: LibFuzzer-based input-fuzzer
- **Build Integration**: Automake conditional (`NEED_FUZZING`)
- **Trigger**: `make check` during OSS-Fuzz build

### Key Findings

1. **No Unit Tests**: tmux has no traditional C unit test framework (no Google Test, CUnit, etc.)
2. **Regression Tests Only**: All tests are functional/integration tests via shell scripts
3. **Fuzzer is Test Code**: The `fuzz/input-fuzzer.c` is a test harness, not production code
4. **Test Isolation**: Tests are well-isolated in `regress/` directory
5. **Clean Separation**: Production code in root, tests in `regress/`, fuzzer in `fuzz/`

### Recommendations

1. **Exclude entire `regress/` directory** from patching (26 test scripts + supporting files)
2. **Exclude entire `fuzz/` directory** from patching (fuzzer harness is test code)
3. **Keep current wildcards** (`**/*test*.c`, etc.) for safety
4. **Add `tools/`** and `presentations/` to exclusion list
5. **Add `example_tmux.conf`** to exclusion list

The current exclusion list in `meta.yaml` is mostly adequate but should be enhanced with:
- `regress/**`
- `fuzz/**`
- `tools/**`
- `presentations/**`
- `logo/**`
- `example_tmux.conf`
- `mdoc2man.awk`

## Production Source Files

**Total**: ~200 source files (C files in root directory)

These are the files that should be considered for patching:
- All `*.c` files in root directory (excluding fuzz/)
- All `*.h` files in root directory
- Source files in `compat/` directory (compatibility layer)

Example production files:
- `tmux.c` - Main entry point
- `input.c` - Terminal input parsing (vulnerability location)
- `screen-write.c` - Screen writing
- `grid.c` - Grid management
- `window.c` - Window management
- `session.c` - Session management
- `server-client.c` - Client-server communication
- And ~190 more production source files

All production code should be eligible for patching according to CRS objectives.
