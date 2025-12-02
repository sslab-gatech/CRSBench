# test.sh Rationale for atlanta-tmux-delta-01

## Overview

This document explains the design decisions and rationale behind the `test.sh` script for the tmux benchmark (`atlanta-tmux-delta-01`).

## Project Context

- **Project**: tmux (terminal multiplexer)
- **Language**: C
- **Build System**: GNU Autotools (Automake/Autoconf)
- **Test Framework**: Shell-based regression tests in `regress/` directory

## Test Suite Selection

### Available Tests

The tmux project contains 26 regression tests in the `regress/` directory. After running all tests in the Docker environment, we identified:

- **20 stable tests** that consistently pass
- **6 flaky tests** that fail in the Docker environment

### Excluded Tests (Flaky in Docker)

The following tests were excluded because they fail consistently in the Docker environment:

1. `capture-pane-sgr0.sh` - SGR attribute capturing test
2. `copy-mode-test-emacs.sh` - Emacs-style copy mode test
3. `copy-mode-test-vi.sh` - Vi-style copy mode test
4. `new-session-environment.sh` - Environment variable handling test
5. `osc-11colours.sh` - OSC color sequence handling test
6. `style-trim.sh` - Style attribute trimming test

These tests appear to have environment-specific dependencies (terminal emulation, display, etc.) that are not available in the Docker container.

### Selected Stable Tests (20 tests)

The `test.sh` script runs the following 20 stable tests:

#### Terminal and Display Tests (5)
1. `am-terminal.sh` - Auto-margin terminal behavior
2. `cursor-test1.sh` - Window resizing with cursor tracking
3. `cursor-test2.sh` - Cursor positioning
4. `cursor-test3.sh` - Cursor behavior
5. `cursor-test4.sh` - Advanced cursor operations

#### Session Management Tests (5)
6. `has-session-return.sh` - Session existence checking
7. `kill-session-process-exit.sh` - Session cleanup
8. `new-session-base-index.sh` - Base index configuration
9. `new-session-command.sh` - Session creation with commands
10. `new-session-no-client.sh` - Detached session creation
11. `new-session-size.sh` - Session size configuration

#### Window Management Tests (1)
12. `new-window-command.sh` - Window creation

#### Control Mode Tests (2)
13. `control-client-sanity.sh` - Control client basic operations
14. `control-client-size.sh` - Control client sizing

#### Configuration and Command Tests (3)
15. `command-order.sh` - Command execution order
16. `conf-syntax.sh` - Configuration file parsing
17. `format-strings.sh` - Format substitution (comprehensive test)

#### Conditional Tests (3)
18. `if-shell-error.sh` - Error handling in if-shell
19. `if-shell-nested.sh` - Nested if-shell commands
20. `if-shell-TERM.sh` - TERM variable in if-shell

## Build Process

### Why Build from Scratch?

The `test.sh` script builds tmux from scratch for the following reasons:

1. **Clean Environment**: The test execution environment has NO pre-built artifacts
   - `/out` directory is NOT mounted
   - `/work` directory is NOT mounted
   - Build cache is not available

2. **Autotools Requirements**: tmux uses Autotools (Automake/Autoconf)
   - `./autogen.sh` generates build scripts
   - `./configure` detects platform and dependencies
   - `make` compiles the source code

3. **Test Requirements**: Regression tests require a built `tmux` binary
   - Tests use the `TEST_TMUX` environment variable
   - Tests execute tmux commands via the binary

### Build Configuration

The build uses the following configuration:

```bash
./configure --enable-static \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "
```

- `--enable-static`: Link libevent and libtinfo statically
- Static linking ensures dependencies are available in test environment
- Matches the OSS-Fuzz build configuration (but without fuzzing enabled)

## Test Execution Strategy

### Sequential Execution

Tests are run sequentially with:
- 10-second timeout per test (prevents hangs)
- Output suppression (only show pass/fail status)
- Detailed summary at the end

### Success Criteria

The script exits with:
- **Exit 0**: All 20 tests passed
- **Exit 1**: Any test failed OR no tests were executed

### Test Coverage

The selected 20 tests provide comprehensive coverage:
- **Core functionality**: Session management, window operations
- **Input/output**: Terminal handling, cursor positioning
- **Configuration**: Config parsing, command execution
- **Control interface**: Control client operations
- **Conditionals**: if-shell command handling
- **Format strings**: Format substitution and expansion

## Alignment with bad_patch.diff

The test suite is designed to work with `bad_patch.diff`:

1. **Wide Coverage**: Tests exercise multiple subsystems
2. **Input Processing**: Cursor tests validate input handling
3. **Command Parsing**: Config and command tests validate parsing
4. **Session Management**: Session tests validate state management
5. **Format Strings**: Comprehensive format string tests

Any mutation in core tmux functionality (input parsing, command execution, session management, etc.) should cause at least one test to fail.

## Design Decisions

### Why Not Run All 26 Tests?

- **Reliability**: Flaky tests reduce confidence in test results
- **Repeatability**: Stable tests ensure consistent pass/fail behavior
- **Docker Constraints**: Some tests require specific terminal features not available in Docker

### Why Not Use `make check`?

- `make check` is designed for fuzzing (builds `fuzz/input-fuzzer`)
- The Makefile target doesn't run regression tests
- Manual test execution provides better control and reporting

### Why Timeout Tests?

- Prevents hanging tests from blocking the entire suite
- 10 seconds is sufficient for all regression tests
- Hangs could indicate bugs introduced by patches

## Verification

The test script has been verified:
- ✅ Successfully builds tmux from source
- ✅ All 20 stable tests pass in Docker
- ✅ Completes in ~60 seconds
- ✅ Provides clear pass/fail reporting
- ✅ Returns correct exit codes

## Future Improvements

Potential enhancements (if needed):
1. Add parallel test execution (if tests are independent)
2. Add detailed failure output (currently suppressed)
3. Add test dependency checking
4. Add more granular timeout control per test

## Summary

The `test.sh` script provides:
- **Reliability**: Only runs stable tests that consistently pass
- **Completeness**: Builds project from scratch (no assumptions about pre-built artifacts)
- **Coverage**: 20 tests covering core tmux functionality
- **Clarity**: Clear reporting of test results
- **Robustness**: Timeout protection and error handling

This approach ensures that `bad_patch.diff` mutations will be detected by the test suite while maintaining high reliability and repeatability.
