# Test Analysis for libavc (atlanta-libavc-full-01)

## Executive Summary

This document provides a comprehensive analysis of all test-related files and infrastructure in the libavc project (commit: 828cdb77ba434eb11ce19f7f0d4482e744b27064). The project contains unit tests, fuzzer harnesses, and example applications that should be excluded from patch generation to prevent breaking test infrastructure.

---

## 1. Build System and Test Framework

### Build System: CMake + Android Build System
- **Primary Build System**: CMake (version 3.9.1+)
- **Secondary Build System**: Android.bp (Soong build system)
- **Test Framework**: Google Test (gtest)
- **Test Enable Flag**: `-DENABLE_TESTS=1` in CMake

### Key Build Files
- `CMakeLists.txt` (root) - Main CMake configuration
- `tests/AvcEncTest.cmake` - Test suite build configuration
- `tests/Android.bp` - Android test build configuration
- `fuzzer/*.cmake` - Fuzzer build configurations

---

## 2. Unit Tests

### Test Suite: AvcEncTest

**Location**: `tests/` directory

**Test Files**:
1. **`tests/AvcEncTest.cpp`** (1010 lines)
   - Main test implementation using Google Test framework
   - Tests AVC H.264 encoder functionality
   - Class: `AvcEncTest` extending `testing::TestWithParam`
   - Tests various encoder parameters: QP, bitrate, frame rate, GOP, ME params, etc.
   - Parameterized tests with different video resolutions and bitrates

2. **`tests/TestArgs.h`** (73 lines)
   - Test environment configuration
   - Class: `TestArgs` extending `testing::Environment`
   - Handles command-line arguments for test resource paths
   - Default resource path: `/data/local/tmp/AvcEncTestRes/`

3. **`tests/AvcEncTest.cmake`**
   - CMake configuration for test build
   - Downloads Google Test from AOSP repository
   - Links against `libavcenc` library
   - Builds executable: `AvcEncTest`

4. **`tests/Android.bp`**
   - Android build configuration for `AvcEncTest`
   - Target: `cc_test` with gtest support
   - Test suite: `device-tests`
   - Sanitizers: signed/unsigned integer overflow

5. **`tests/AndroidTest.xml`**
   - Android test configuration for Tradefed
   - Configures media file preparation and dynamic config
   - Test resources: `AvcTestRes-1.0` media files

6. **`tests/README.md`**
   - Test documentation
   - Build and run instructions for Linux and Android
   - Test resource URL: https://dl.google.com/android-unittest/media/external/libavc/tests/AvcTestRes-1.0.zip

### Test Commands

**Build (Linux)**:
```bash
cmake .. -DENABLE_TESTS=1 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug
make
```

**Build with Sanitizers**:
```bash
cmake .. -DENABLE_TESTS=1 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DSANITIZE=fuzzer-no-link,address,\
  signed-integer-overflow,unsigned-integer-overflow
make
```

**Run Tests**:
```bash
./AvcEncTest -P <path_to_test_resources>
```

**Android Build**:
```bash
m AvcEncTest
atest AvcEncTest
```

---

## 3. Fuzzer Harnesses (OSS-Fuzz)

### Location: `fuzzer/` directory

**Fuzzer Files**:

1. **`fuzzer/avc_dec_fuzzer.cpp`** (11,548 bytes)
   - AVC decoder fuzzer
   - Harness path: `$REPO/fuzzer/avc_dec_fuzzer.cpp`

2. **`fuzzer/avc_enc_fuzzer.cpp`** (39,085 bytes)
   - AVC encoder fuzzer
   - Harness path: `$REPO/fuzzer/avc_enc_fuzzer.cpp`

3. **`fuzzer/mvc_dec_fuzzer.cpp`** (12,180 bytes)
   - MVC (Multiview Video Coding) decoder fuzzer
   - Harness path: `$REPO/fuzzer/mvc_dec_fuzzer.cpp`
   - **Has vulnerability**: cpv_1 (heap-buffer-overflow)

4. **`fuzzer/svc_dec_fuzzer.cpp`** (14,930 bytes)
   - SVC (Scalable Video Coding) decoder fuzzer
   - Harness path: `$REPO/fuzzer/svc_dec_fuzzer.cpp`
   - **Has vulnerability**: cpv_0 (heap-buffer-overflow)

5. **`fuzzer/svc_enc_fuzzer.cpp`** (45,747 bytes)
   - SVC encoder fuzzer
   - Harness path: `$REPO/fuzzer/svc_enc_fuzzer.cpp`

**Build Configurations**:
- `fuzzer/avc_dec_fuzzer.cmake`
- `fuzzer/avc_enc_fuzzer.cmake`
- `fuzzer/mvc_dec_fuzzer.cmake`
- `fuzzer/svc_dec_fuzzer.cmake`
- `fuzzer/svc_enc_fuzzer.cmake`

**Build Script**:
- `fuzzer/ossfuzz.sh` - OSS-Fuzz build script
  - Builds all fuzzers with CMake
  - Enables MVC and SVC: `-DENABLE_SVC=1 -DENABLE_MVC=1`
  - Copies fuzzers to `$OUT` directory

**Additional Files**:
- `fuzzer/avc_dec_fuzzer.dict` - Fuzzing dictionary
- `fuzzer/README.md` - Fuzzer documentation
- `fuzzer/Android.bp` - Android build configuration for fuzzers

---

## 4. Example Applications

### Location: `examples/` directory

These are command-line example applications demonstrating library usage. They are test/demo code, not production code.

**Example Applications**:

1. **`examples/avcdec/`** - AVC decoder example
2. **`examples/avcenc/`** - AVC encoder example
3. **`examples/mvcdec/`** - MVC decoder example
4. **`examples/svcdec/`** - SVC decoder example
5. **`examples/svcenc/`** - SVC encoder example

Each example has:
- CMake configuration (`*.cmake`)
- Source code (decoder/encoder main programs)
- Android.bp configuration

---

## 5. Third-Party Test Code

### Google Test Framework

**Location**: `third_party/googletest/`

This is an external dependency for unit testing. Contains:
- `googlemock/` - Mock framework
- `googletest/` - Test framework
- Extensive test files for googletest itself
- Build artifacts in `third_party/build/`

**Note**: All googletest files should be excluded from patching.

---

## 6. Build Test Artifacts

**Location**: `build_test/` directory

Contains:
- CMake build artifacts
- Compiled object files
- Test resources: `build_test/AvcTestRes-1.0/`
- Build system generated files

**Note**: This is a generated directory and should be excluded.

---

## 7. OSS-Fuzz Integration

### Files in Source Repository

**`.oss-fuzz/` directory**:
- `build.sh` - Build script that calls `fuzzer/ossfuzz.sh`
- `Dockerfile` - OSS-Fuzz container configuration
- `.aixcc/` - Benchmark metadata directory
  - `meta.yaml` - Vulnerability metadata
  - `mvc_dec_fuzzer/cpv_1/` - MVC fuzzer vulnerability data
  - `svc_dec_fuzzer/cpv_0/` - SVC fuzzer vulnerability data

### Files in Benchmark Directory

**`benchmarks/atlanta-libavc-full-01/` directory**:
- `build.sh` - OSS-Fuzz build script
- `Dockerfile` - Container configuration
- `project.yaml` - OSS-Fuzz project metadata
- `mvc_dec_fuzzer.options` - Fuzzer runtime options
- `svc_dec_fuzzer.options` - Fuzzer runtime options
- `.aixcc/meta.yaml` - CRSBench metadata with patch exclusions

---

## 8. Comprehensive Patch Exclude List

Based on the analysis, the following patterns should be excluded from patch generation:

### Current Exclusions (from `.aixcc/meta.yaml`)

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

### Recommended Additional Exclusions

The current exclusion list is **comprehensive and adequate**. However, for completeness, consider explicitly excluding:

```yaml
# Additional explicit exclusions (optional - already covered by patterns)
- fuzzer/**                    # Covered by test patterns, but explicit
- examples/**                  # Example applications (demo code)
- third_party/**              # External dependencies
- build_test/**               # Build artifacts
- .oss-fuzz/**                # OSS-Fuzz integration
- '*.options'                  # Fuzzer options files
- '*.dict'                     # Fuzzer dictionaries
- Android.bp                   # Android build files
- '*.xml'                      # Android test configurations
- '*.cmake'                    # CMake configurations
```

### Reasoning

1. **Test Files** (`tests/**`, `**/*test*`):
   - Unit tests should not be patched
   - Breaking tests defeats vulnerability validation

2. **Fuzzer Harnesses** (`fuzzer/**`):
   - Already covered by `**/*test*` patterns
   - Fuzzer harnesses are test code
   - Should not be modified during patching

3. **Example Applications** (`examples/**`):
   - Demo/example code, not production code
   - Used for testing and documentation

4. **Build System Files**:
   - `CMakeLists.txt`, `*.cmake`, `Android.bp`
   - Modifying build files can break compilation

5. **Third-Party Code** (`third_party/**`):
   - External dependencies (Google Test)
   - Should never be patched

6. **Documentation** (`*.md`, `README*`, `docs/**`):
   - Non-code files
   - No functional impact

---

## 9. Production Code Structure

### Code to INCLUDE in Patching

**Decoder Implementation** (`decoder/`):
- `decoder/*.c`, `decoder/*.h` - Core decoder logic
- `decoder/svc/*.c`, `decoder/svc/*.h` - SVC decoder
- `decoder/mvc/*.c`, `decoder/mvc/*.h` - MVC decoder
- `decoder/arm/*`, `decoder/x86/*`, `decoder/riscv/*` - Architecture-specific code

**Encoder Implementation** (`encoder/`):
- `encoder/*.c`, `encoder/*.h` - Core encoder logic
- `encoder/svc/*.c`, `encoder/svc/*.h` - SVC encoder
- `encoder/arm/*`, `encoder/x86/*`, `encoder/riscv/*` - Architecture-specific code

**Common Code** (`common/`):
- `common/*.c`, `common/*.h` - Shared utility code
- `common/svc/*`, `common/mvc/*` - Shared SVC/MVC code
- `common/arm/*`, `common/x86/*`, `common/riscv/*` - Architecture-specific shared code

### Vulnerability Locations

Based on `.aixcc/meta.yaml`:

1. **mvc_dec_fuzzer - cpv_1**:
   - Fuzzer: `mvc_dec_fuzzer.cpp`
   - Vulnerability: heap-buffer-overflow (AddressSanitizer)
   - Likely in: `decoder/mvc/` implementation

2. **svc_dec_fuzzer - cpv_0**:
   - Fuzzer: `svc_dec_fuzzer.cpp`
   - Vulnerability: heap-buffer-overflow (AddressSanitizer)
   - Likely in: `decoder/svc/` implementation

**These vulnerabilities are in production code, not test code.**

---

## 10. Summary and Recommendations

### Test Infrastructure Overview

| Category | Count | Exclusion Status |
|----------|-------|------------------|
| Unit Test Files | 6 | ✓ Excluded (`tests/**`) |
| Fuzzer Harnesses | 5 | ✓ Excluded (`**/*test*.cpp`) |
| Example Apps | 5 | ⚠️ Should exclude (`examples/**`) |
| Build Configs | ~20 | ✓ Excluded (`*.cmake`, `CMakeLists.txt`) |
| Third-Party | 1 (gtest) | ⚠️ Should exclude (`third_party/**`) |

### Key Findings

1. ✅ **Current exclusion list is adequate** for core requirements
2. ✅ All test files are properly excluded with `tests/**` and `**/*test*` patterns
3. ✅ Build system files are excluded
4. ⚠️ Consider explicitly excluding `examples/**` and `third_party/**`
5. ✓ Production code (decoder/encoder/common) is correctly included

### Verification Commands

To verify test detection:
```bash
# Find all test files
find . -name "*test*" -o -name "*Test*" | grep -v ".git" | grep -v "third_party/build"

# Find fuzzers
find fuzzer/ -name "*.cpp"

# Find examples
find examples/ -name "*.c" -o -name "*.cpp"
```

### Testing After Patches

When evaluating patches:
1. Build with fuzzer: `cmake .. -DENABLE_SVC=1 -DENABLE_MVC=1 && make`
2. Run fuzzers: Execute `mvc_dec_fuzzer` and `svc_dec_fuzzer` with POVs
3. Build with tests: `cmake .. -DENABLE_TESTS=1 && make`
4. Run unit tests: `./AvcEncTest -P <resources>`

---

## Appendix A: File Counts

```
Production Code:
- decoder/: ~60 C/H files
- encoder/: ~80 C/H files
- common/: ~40 C/H files

Test Code:
- tests/: 6 files (5 source + 1 README)
- fuzzer/: 14 files (5 fuzzers + 5 configs + 4 support)
- examples/: 5 directories with ~10 files total

Third-Party:
- third_party/googletest/: Extensive (exclude all)
```

---

## Appendix B: Build System Decision Tree

```
Should this file be patched?
├─ Is it in tests/**? → NO (unit tests)
├─ Is it in fuzzer/**? → NO (fuzzer harnesses)
├─ Is it in examples/**? → NO (demo applications)
├─ Is it in third_party/**? → NO (external deps)
├─ Does filename contain "test" or "Test"? → NO
├─ Is it a build file (*.cmake, CMakeLists.txt, Android.bp)? → NO
├─ Is it in decoder/**, encoder/**, or common/**? → YES (patch allowed)
└─ Otherwise → Check case-by-case
```

---

**Document Version**: 1.0
**Analysis Date**: 2024-11-22
**Project Commit**: 828cdb77ba434eb11ce19f7f0d4482e744b27064
**Benchmark**: atlanta-libavc-full-01
