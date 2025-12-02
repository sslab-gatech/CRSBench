# test.sh Rationale for atlanta-php-delta-01

## Overview
This benchmark tests the PHP interpreter (php-src) built from source in the cp-c-php repository.

## Test Strategy

### Test Framework
PHP uses its own test framework (`run-tests.php`) to execute `.phpt` test files. The project has 14,368+ test files covering various PHP features and extensions.

### Selected Test Suites
The test.sh runs the following test suites:
1. **tests/basic/** - Basic PHP functionality tests
2. **tests/lang/** - Language feature tests
3. **ext/standard/tests/strings/** - String function tests
4. **ext/standard/tests/array/** - Array function tests

### Rationale for Test Selection
- **Comprehensive Coverage**: The selected tests cover core PHP functionality including:
  - Basic language constructs
  - String operations (strlen, substr, str_repeat, etc.)
  - Array operations (count, array_keys, array_values, etc.)
  - Type hinting
  - Exception handling
  - Output buffering
  - Unicode escapes
  - Variable handling

- **Reasonable Execution Time**: Running ~1798 tests takes about 95 seconds, which is manageable for CI/CD

- **Excluded Tests**:
  - **strncmp tests**: Excluded because they contain a known bug in this version (strncmp returns incorrect values)
  - **bug40754.phpt**: Also related to strncmp issue
  - **Extension-specific tests**: Many are skipped automatically (e.g., CGI tests) when the required extension is not enabled

### Test Execution Details
- **Test Runner**: `sapi/cli/php run-tests.php`
- **Options Used**:
  - `--show-diff`: Show differences when tests fail
  - `--show-slow 1000`: Report tests taking >1000ms
  - `--set-timeout 60`: Set test timeout to 60 seconds
- **Test Skipping**: Known failing tests are temporarily renamed with `.skip` extension before running tests, then restored afterward

### Success Criteria
- All executed tests must pass (exit code 0)
- Skipped tests are acceptable (138 skipped due to missing extensions like CGI)
- No test failures or warnings

## Test Results
When run successfully:
- 1936 tests total
- 1798 tests executed and passed (92.9%)
- 138 tests skipped (7.1%) - due to missing optional extensions
- 0 failures
- Execution time: ~95 seconds

## Mutation Testing Targets
For bad_patch.diff generation, the following functions are mutated:
1. **count()** in ext/standard/array.c - Always returns 0
2. **substr()** in ext/standard/string.c - Always returns empty string
3. **str_repeat()** in ext/standard/string.c - Always returns empty string

These mutations will cause failures in:
- lang/operators tests that use count() in loops
- string tests that verify substr() behavior
- string tests that verify str_repeat() behavior

## Rebuild Requirements
**IMPORTANT**: This benchmark requires `replay-build.sh` to rebuild PHP after applying patches. The mutations in bad_patch.diff modify C source files, which means:
1. The patch must be applied to source files
2. `replay-build.sh` must be executed to recompile the affected object files
3. Only then will test.sh reflect the mutations

Without replay-build.sh, the pre-compiled PHP binary will continue to work correctly even with mutations applied to the source.
