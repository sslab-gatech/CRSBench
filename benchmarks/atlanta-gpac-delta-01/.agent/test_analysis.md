# Test Analysis for GPAC (cp-c-gpac-f85c2ee9)

## Executive Summary

GPAC has a comprehensive external test suite in a separate git submodule repository (`https://github.com/gpac/testsuite`). The project also contains unit test filters for internal testing and sample demonstration applications (testapps). The main test suite requires the git submodule to be initialized and contains functional/regression tests that exercise the GPAC framework.

## Test Infrastructure

### Build System
- **Build System**: Autotools (configure script + Makefiles)
- **Primary Test Target**: `make test_suite` (line 80-81 in Makefile)
- **Alternative Test Target**: `make travis_tests` (line 100-102 in Makefile)
- **Test Framework**: Custom shell script-based test suite

### Test Suite Location
The main test suite is located in a **git submodule** at `testsuite/`:
- **Repository**: https://github.com/gpac/testsuite
- **Branch**: master (filters branch for CI)
- **Status**: Not initialized in the current repository (indicated by `-` prefix in `git submodule status`)
- **Initialization Command**: `git submodule update --init`

### Test Execution Commands

From the main Makefile:

```bash
# Primary test command
make test_suite
# Executes: cd $(SRC_PATH)/testsuite && ./make_tests.sh -precommit -p=0

# Travis CI test command
make travis_tests
# Executes: cd $(SRC_PATH)/testsuite && ./make_tests.sh -precommit -p=0

# Full Travis CI workflow with coverage
make travis
# Executes: travis_tests lcov travis_deploy
```

### Test Configuration

The test suite requires:
1. **Git submodule initialized**: The testsuite directory must be populated
2. **GPAC binaries built**: MP4Box and gpac executables must be available
3. **External media files**: The test suite uses media files in `media/` and `external_media/` directories
4. **Test scripts**: Shell scripts in `testsuite/scripts/*.sh`

From `.travis.yml` (line 37-39):
```yaml
before_script:
  - "git -C ./testsuite checkout filters"
  - xvfb-run -e /dev/stdout --auto-servernum --server-num=1 glxinfo
env: GPAC_CONFIGURE_OPTIONS="--enable-mem-track --enable-gcov" ... DOTRAVIS="make travis"
```

## Test Categories

### 1. External Functional Test Suite (Primary)
**Location**: `testsuite/` (git submodule)
**Type**: Functional/Regression tests
**Framework**: Custom shell script-based

**Test Structure** (based on GitHub repo):
- `scripts/*.sh` - Individual test scripts
- `media/` - Test media files
- `external_media/` - Additional media resources (~300MB)
- `hash_refs/` - SHA-1 hash references for regression testing
- `rules/` - Customization files and expected error patterns
- `oss-fuzzers/` - Fuzzing test implementations

**Test Types**:
- Simple command tests (`single_test`)
- Aggregated multi-step tests (`test_begin`, `do_test`, `test_end`)
- Hash-based regression tests (SHA-1 checksum comparisons)
- Playback/media tests (`do_play_test`)
- UI/interactivity tests for SVG and BIFS

### 2. Unit Test Filters (Built-in)
**Location**: `src/filters/unit_test_filter.c`
**Type**: Unit tests for filter framework
**Purpose**: Internal testing of GPAC's filter system

**Features**:
- Tests filter packet handling
- Tests filter PID (Packet ID) management
- SHA-1 hash validation
- Packet lifecycle testing (creation, forwarding, deletion)
- Property enumeration testing

**Modes**:
- Source mode (UTF_MODE_SOURCE)
- Sink mode (UTF_MODE_SINK)
- Filter mode (UTF_MODE_FILTER)

### 3. Test Filter Module
**Location**: `modules/test_filter/test_filter.c`
**Type**: Dynamic library test module
**Purpose**: Tests loading of filters from dynamic libraries

**Functionality**:
- Sink filter for consuming any stream except files
- Tests filter event handling
- Tests packet processing
- Validates dynamic filter loading mechanism

### 4. NodeJS Binding Tests
**Location**: `share/nodejs/test/gpac.js`
**Type**: NodeJS API tests
**Purpose**: Tests GPAC NodeJS bindings

**Test Modes**:
- Blocking mode (RUN_SYNC)
- Non-blocking step mode (RUN_STEP)
- Promise-based async mode (RUN_PROMISE)

**Test Types**:
- Simple session tests (TEST_SIMPLE)
- Sink tests (TEST_SINK)
- Forward tests (TEST_FORWARD)
- Custom DASH algorithm tests
- Custom HTTP request handler tests
- FileIO wrapper tests

**Execution**:
```bash
node share/nodejs/test/gpac.js [options]
```

### 5. GUI Extension Tests
**Location**:
- `share/gui/extensions/bifs_tests/bifs_tests.js`
- `share/gui/extensions/dashif/dashif_tests.js`

**Type**: JavaScript GUI tests
**Purpose**: Tests BIFS (Binary Format for Scenes) and DASH-IF functionality

### 6. Test Applications (Sample Programs)
**Location**: `applications/testapps/`
**Type**: Demonstration/sample applications (NOT unit tests)
**Purpose**: Example programs showing API usage

**Applications**:
- `bmp4demux/` - MP4 demultiplexing example
- `fmp4demux/` - Fragmented MP4 demultiplexing
- `segmp4demux/` - Segmented MP4 demultiplexing
- `atscdmx/` - ATSC demultiplexing
- `broadcaster/` - RTP broadcasting example
- `hevcbench/` - HEVC benchmarking
- `loadcompare/` - Load comparison tool
- `mp4mux/` - MP4 multiplexing example
- `mpedemux/` - MPEG demultiplexing
- `mpeg2ts/` - MPEG-2 Transport Stream handling
- `svg2bifs/` - SVG to BIFS conversion
- `ts2hds/` - TS to HDS conversion
- `ts2udp/` - TS to UDP streaming
- `udptsseg/` - UDP TS segmentation
- `dmbrs/` - DMB broadcast receiver
- `largefile/` - Large file handling test

**Note**: These are NOT regression tests but API demonstration programs.

## Test Execution Requirements

### Prerequisites
1. Configure with test support:
   ```bash
   ./configure --enable-mem-track --enable-gcov  # For coverage
   # OR
   ./configure  # Standard build
   ```

2. Build GPAC:
   ```bash
   make
   make install  # Or sudo make install
   ```

3. Initialize test suite submodule:
   ```bash
   git submodule update --init
   cd testsuite
   git checkout filters  # For filter tests
   ```

### Running Tests

**Standard test execution**:
```bash
make test_suite
```

**With coverage tracking**:
```bash
make lcov_clean          # Clean coverage counters
make test_suite          # Run tests
make lcov                # Generate coverage report
```

**Travis CI mode (with X virtual framebuffer)**:
```bash
xvfb-run -e /dev/stdout --auto-servernum --server-num=1 \
  --server-args="-screen 0 1024x768x24" make travis
```

**Direct test suite execution**:
```bash
cd testsuite
./make_tests.sh -precommit -p=0
```

### Test Environment
- **Display**: X server required (or Xvfb for headless)
- **Audio**: AUDIODEV=null for headless testing
- **Graphics**: GLX support for 3D tests
- **Dependencies**: See `.travis.yml` for required packages

## Patch Exclusion List

### Comprehensive Exclusion Patterns

Based on the analysis and existing `.aixcc/meta.yaml`, here is the recommended patch exclusion list:

```yaml
patch_exclude_list:
  # Build system files
  - build.sh
  - Makefile
  - "*/Makefile"
  - CMakeLists.txt
  - "*/CMakeLists.txt"
  - configure
  - configure.*
  - "*.ac"
  - "*.am"
  - "*.m4"
  - config.h.in
  - "*.mak"
  - "*.cmake"

  # VCS and metadata
  - .gitignore
  - .gitattributes
  - .gitmodules
  - .aixcc/**
  - .github/**
  - .travis.yml

  # Test infrastructure
  - testsuite/**
  - test/**
  - tests/**

  # Test source files
  - "**/*test*.c"
  - "**/*test*.cc"
  - "**/*test*.cpp"
  - "**/*test*.h"
  - "**/*test*.hpp"

  # Specific test files and directories
  - src/filters/unit_test_filter.c
  - modules/test_filter/**
  - applications/testapps/**
  - share/nodejs/test/**
  - share/gui/extensions/bifs_tests/**
  - share/gui/extensions/dashif/dashif_tests.js

  # Documentation
  - docs/**
  - doc/**
  - "*.md"
  - README*
  - CHANGELOG*
  - Changelog
  - COPYING
  - LICENSE*
  - AUTHORS
  - CONTRIBUTORS
  - INSTALL
  - NEWS

  # Packaging and distribution
  - debian/**
  - packagers/**
  - "*.spec"
  - "*.nix"
  - flake.*
  - generate_installer.bat
  - version.bat
  - manifest.rc
  - mkdmg.sh

  # Development utilities
  - change_version.sh
  - check_revision.sh
  - run_configure.sh

  # IDE and build artifacts
  - "*.sln"
  - "*.vcxproj"
  - "*.vcxproj.filters"
  - "*.xcodeproj/**"
  - build/**
  - "*.dep"

  # Media and resource files (not source code)
  - "*.mp4"
  - "*.png"
  - "*.jpg"
  - "*.jpeg"
  - "*.gif"
  - "*.svg"
  - "*.wav"
  - "*.mp3"
  - share/res/**
  - share/media/**
  - media/**

  # Scripts and GUI
  - share/scripts/**
  - share/gui/**
  - share/python/**
  - share/vis/**

  # Generated files
  - include/gpac/revision.h
```

### Exclusion Rationale

1. **Test Infrastructure**: All test-related code should be excluded to avoid breaking test functionality
2. **Build System**: Build files should not be modified to maintain build reproducibility
3. **Test Applications**: The testapps are sample programs, not core functionality
4. **Documentation**: Documentation files don't affect functionality
5. **External Test Suite**: The git submodule `testsuite/` contains all regression tests
6. **Media Files**: Binary media files are test fixtures, not source code

### Verification Commands

To verify the patch exclusion list catches all test-related files:

```bash
# Find test C/C++ source files (should all be excluded)
find . -name "*test*.c" -o -name "*test*.cpp" -o -name "*test*.h"

# Check test directories (should all be excluded)
find . -type d -name "*test*"

# List testapps (should all be excluded)
ls -la applications/testapps/

# Check testsuite status
git submodule status
```

## Test Analysis for Patch Generation

### Critical Non-Test Code (Should NOT be excluded)

The following contain "test" in their names but are NOT test code:

**NONE FOUND** - All files with "test" in their names are actually test-related and should be excluded.

### Test Detection Methodology

Files were classified as tests based on:
1. Location in `test*` or `*test*` directories
2. Filename patterns: `*test*.{c,cpp,h,js,py,sh}`
3. Purpose analysis: unit tests, sample programs, test fixtures
4. Documentation references (README.md, Makefile comments)
5. Build system configuration (Makefile test targets)

## Recommended test.sh Implementation

Since GPAC has an extensive external test suite, the recommended `test.sh` should:

```bash
#!/bin/bash
set -e

# Check if testsuite submodule is initialized
if [ ! -f testsuite/make_tests.sh ]; then
    echo "Error: testsuite submodule not initialized"
    echo "Run: git submodule update --init"
    exit 1
fi

# Run the precommit test suite
cd testsuite
./make_tests.sh -precommit -p=0

echo "Tests completed successfully"
```

**Alternative minimal test** (if submodule unavailable):
```bash
#!/bin/bash
set -e

# Verify binaries were built successfully
if [ ! -f bin/gcc/MP4Box ]; then
    echo "Error: MP4Box binary not found"
    exit 1
fi

if [ ! -f bin/gcc/gpac ]; then
    echo "Error: gpac binary not found"
    exit 1
fi

# Run basic smoke tests
./bin/gcc/MP4Box -version
./bin/gcc/gpac -h

echo "Basic smoke tests passed"
```

## Summary

- **Primary Test Suite**: External git submodule (`testsuite/`) with comprehensive shell script-based tests
- **Test Command**: `make test_suite` or `cd testsuite && ./make_tests.sh -precommit -p=0`
- **Test Types**: Functional, regression, hash-based, playback, UI tests
- **Additional Tests**: Unit test filters, NodeJS binding tests, GUI tests
- **Test Applications**: 18 sample programs in `applications/testapps/` (not unit tests)
- **Submodule Required**: Yes, must run `git submodule update --init` first
- **Coverage Support**: Yes, via `make lcov` with gcov instrumentation
- **CI Integration**: Travis CI configured with xvfb for headless testing

## Files Cataloged

### Test Source Files (2 files)
1. `src/filters/unit_test_filter.c` - Unit test filter implementation
2. `modules/test_filter/test_filter.c` - Dynamic library test module

### Test Scripts (3 files)
1. `share/nodejs/test/gpac.js` - NodeJS binding tests
2. `share/gui/extensions/bifs_tests/bifs_tests.js` - BIFS GUI tests
3. `share/gui/extensions/dashif/dashif_tests.js` - DASH-IF GUI tests

### Test Applications (18 directories)
All in `applications/testapps/`:
- atscdmx, bmp4demux, broadcaster, dmbrs, fmp4demux, hevcbench, largefile
- loadcompare, mp4mux, mpedemux, mpeg2ts, segmp4demux, svg2bifs
- ts2hds, ts2udp, udptsseg

### Test Directories (4 directories)
1. `testsuite/` - External test suite (git submodule)
2. `applications/testapps/` - Sample programs
3. `share/nodejs/test/` - NodeJS tests
4. `modules/test_filter/` - Test filter module

### Build System Test Targets
- `make test_suite` (line 80-81)
- `make travis_tests` (line 100-102)
- `make travis` (line 108) - Full CI workflow

## Conclusion

GPAC has a robust testing infrastructure centered around an external test suite in a git submodule. The project has proper functional/regression tests that should be used for validation. All test-related files have been identified and should be excluded from patch generation to avoid breaking the test infrastructure.

The recommended approach is to:
1. Use the existing `make test_suite` target for functional testing
2. Exclude all test files as specified in the comprehensive patch exclusion list
3. Ensure the testsuite submodule is initialized before running tests
4. Consider coverage analysis with `make lcov` for thorough validation
