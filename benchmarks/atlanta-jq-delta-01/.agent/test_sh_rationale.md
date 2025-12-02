# test.sh Rationale for atlanta-jq-delta-01

## Overview
This test.sh script builds jq from source and runs its comprehensive test suite to verify correctness.

## Build Process
1. **Copy oniguruma dependency**: Removes any existing modules directory and copies fresh oniguruma source from /src/oniguruma
2. **Generate build files**: Runs `autoreconf -fi` to generate configure scripts
3. **Configure**: Runs `./configure --with-oniguruma=builtin` which automatically configures both jq and the embedded oniguruma library
4. **Build**: Runs `make -j$(nproc)` which builds both oniguruma (as a submodule) and jq

## Test Execution
The script runs `make check` which executes jq's test suite including:
- tests/mantest: Tests from the jq manual
- tests/jqtest: Core jq functionality tests
- tests/shtest: Shell-based integration tests
- tests/utf8test: UTF-8 handling tests
- tests/base64test: Base64 encoding/decoding tests
- tests/optionaltest: Optional feature tests (if available)

## Key Design Decisions

### Why remove and recreate modules directory?
The Docker image may have a stale or symlinked modules directory. Removing it ensures we start with a clean slate and the oniguruma dependency is properly copied.

### Why use --with-oniguruma=builtin?
This configuration option tells jq's configure script to build oniguruma as part of the build process. The configure script automatically:
- Detects the oniguruma sources in modules/oniguruma
- Runs configure for oniguruma as a subproject
- Builds oniguruma before building jq
- Links jq against the built oniguruma library

This approach is simpler than manually building oniguruma separately.

### Why make check instead of individual test scripts?
`make check` is the standard way to run jq's test suite. It:
- Runs all configured tests in the correct order
- Handles test dependencies automatically
- Provides consistent test execution

## Expected Behavior
- Build should complete without errors
- All tests should pass
- Script exits with code 0 on success, non-zero on failure
