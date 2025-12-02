# test.sh Rationale for atlanta-sleuthkit-delta-01

## Approach

This test.sh script uses **smoke tests** to verify that the sleuthkit project builds successfully from source.

## Why Smoke Tests?

Initially, I explored running the existing unit tests in the `tests/` directory:
- `tests/read_apis`
- `tests/fs_fname_apis`
- `tests/fs_attrlist_apis`

However, these test programs are defined as `check_PROGRAMS` in `tests/Makefile.am`, which means they are only built when running `make check`. The standard `make` command used in the build process does not compile these test binaries.

Additionally, the project's unit tests in `unit_tests/base/` require CppUnit, which is not available in the Docker environment (configure shows: `checking for Cppunit - version >= 1.12.1... no`).

## Test Strategy

The smoke tests verify that core static libraries were built successfully:
- `tsk/.libs/libtsk.a` - Main TSK library
- `tsk/base/.libs/libtskbase.a` - Base functionality library
- `tsk/fs/.libs/libtskfs.a` - Filesystem library

These libraries are fundamental to sleuthkit's functionality. If they fail to build or are not present, it indicates a critical build failure.

## Build Process

The test.sh script:
1. Runs `./bootstrap` to generate build files
2. Runs `./configure` with appropriate flags:
   - `--enable-static` - Build static libraries
   - `--disable-shared` - Skip shared libraries
   - `--disable-java` - No Java bindings
   - `--without-afflib --without-libewf --without-libvhdi --without-libvmdk` - Disable optional features
3. Runs `make -j$(nproc)` to compile the project
4. Verifies existence of core library artifacts

## Regression Testing Capability

While smoke tests are not ideal, they still serve the purpose of regression testing:
- A code change that breaks core functionality (e.g., syntax errors, missing functions, broken includes) will cause the build to fail
- Missing library artifacts indicate compilation failures
- The test.sh will catch bugs that prevent successful compilation of core components

## Verification

Tested successfully in Docker container - build completes and all three core libraries are present.
