# test.sh Rationale for atlanta-gpac-delta-01

## Test Suite Analysis

### Search Process
I conducted an exhaustive search for existing unit tests in the GPAC project:

1. **Checked testsuite directory**: `/testsuite` exists but is empty
2. **Checked Makefile**: Found `test_suite` target that references `./testsuite/make_tests.sh`, but the script is missing
3. **Checked for test frameworks**: No pytest, CMake tests, or other test frameworks found
4. **Checked testapps**: Found `/applications/testapps` with sample applications (not automated tests)
5. **Checked test modules**: Found `unit_test_filter.c` which is a filter module, not a test framework

### Conclusion
**No unit test suite is available in this project.** The GPAC project has an external test suite at https://github.com/gpac/testsuite, but it's not included in this source tree.

## Test Strategy: Functional Smoke Tests

Since no unit tests exist, I created **functional smoke tests** as a LAST RESORT. These tests verify core GPAC functionality rather than just checking if binaries exist.

### Tests Implemented

1. **Build from scratch**:
   - Runs `./configure --static-build`
   - Runs `make -j$(nproc)`
   - Verifies this is a clean build (no pre-built artifacts assumed)

2. **Build artifact verification**:
   - Checks for `libgpac_static.a` (core library)
   - Checks for `MP4Box` binary (main tool)

3. **MP4Box functionality tests**:
   - `MP4Box -version`: Tests basic execution
   - `MP4Box -add`: Tests ISO media file creation (exercises `gf_isom_*` functions)
   - `MP4Box -info`: Tests ISO media file parsing (exercises `gf_isom_open_file`)

4. **gpac application tests**:
   - `gpac -h`: Tests help output
   - `gpac -ltf`: Tests filter loading (exercises filter system)

### Functions Tested

Based on the fuzzer harnesses, these tests exercise:
- `gf_isom_open_file()`: ISO media file opening/parsing
- `gf_isom_close()`: ISO media file closing
- ISO media file creation/manipulation
- Filter system initialization and loading

### Why This Approach

1. **NO OVERFITTING**: Tests use standard GPAC commands, not custom checks
2. **FUNCTIONALITY FOCUS**: Tests verify that core features work, not just that builds succeed
3. **COVERAGE**: Tests cover the same functionality that fuzzers target
4. **REGRESSION DETECTION**: Will fail if core parsing/filtering logic breaks

## Test Execution

The test.sh script:
- Runs in a CLEAN environment (no /out or /work directories)
- Builds the project from scratch first
- Tests actual functionality using built binaries
- Exits with code 0 on success, non-zero on failure

## Limitations

As a smoke test, this has limited coverage compared to a full unit test suite. However, it's the best approach given:
1. No existing test infrastructure in the source tree
2. The need to test FUNCTIONALITY (not just build success)
3. The requirement to detect regressions in core features
