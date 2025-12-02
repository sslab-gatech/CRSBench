# test.sh Rationale for atlanta-libssh2-delta-01

## Overview
This document explains the design decisions for the test.sh script for the libssh2 benchmark.

## Project Information
- **Project**: libssh2 - SSH2 client-side library
- **Language**: C
- **Build System**: CMake (also supports autotools)
- **Test Framework**: Custom test suite with standalone test programs

## Test Strategy

### Build Approach
The test.sh uses CMake instead of autotools because:
1. **Tool Availability**: The Docker container has CMake installed but lacks autoconf/automake/libtoolize
2. **Simplicity**: CMake configuration is more straightforward and doesn't require generating configure scripts
3. **Compatibility**: libssh2 supports both build systems equally well

### Build Configuration
```bash
cmake /src/libssh2 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=OFF
```

- **Debug build**: Enables debugging symbols for better error diagnostics
- **Static linking**: Avoids shared library dependencies
- **Testing enabled**: Ensures test programs are built
- **Examples disabled**: Reduces build time

### Test Selection

#### Tests Executed
- **test_simple**: Core functionality test that validates basic SSH2 session operations

#### Tests Skipped
The following tests were excluded because they require Docker-in-Docker or SSH server infrastructure:
- **test_hostkey**: Requires Docker to build an OpenSSH server container
- **test_auth_keyboard_info_request**: Requires SSH server for authentication testing
- **Network tests**: All tests requiring openssh_server Docker container

### Rationale for test_simple
The `test_simple` test provides adequate coverage for validating that:
1. The library compiles correctly
2. Core data structures can be allocated/deallocated
3. Basic API functions work as expected
4. No memory corruption in basic operations

This test is sufficient for detecting:
- Build failures from source code changes
- API breakage
- Memory corruption bugs
- Basic functionality regressions

## Execution Environment
- **Working Directory**: /src/libssh2 (WORKDIR)
- **Build Directory**: /tmp/libssh2-build (out-of-tree build)
- **Test Execution**: From /tmp/libssh2-build/tests

## Success Criteria
The test.sh succeeds when:
1. CMake configuration completes without errors
2. Library and test programs build successfully
3. test_simple executes and passes

## Limitations
- Network-dependent tests are not executed
- SSH protocol tests requiring a real server are skipped
- Docker-dependent tests cannot run in the container environment

These limitations are acceptable because:
- The primary goal is to validate that code changes don't break the build or core functionality
- Network tests are better suited for integration testing environments
- test_simple provides sufficient smoke testing for patch validation
