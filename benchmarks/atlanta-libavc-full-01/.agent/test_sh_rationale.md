# test.sh Rationale for atlanta-libavc-full-01

## Project Overview
- **Project**: libavc (H.264/AVC video encoder/decoder library)
- **Language**: C/C++
- **Test Framework**: GoogleTest
- **Build System**: CMake

## Test Suite Analysis

### Available Tests
The project has a GoogleTest-based test suite in `tests/AvcEncTest.cpp` that validates the AVC encoder functionality:
- **Test Suite**: `AvcEncTest`
- **Test Cases**: 2 parameterized tests
  - `EncodeTest/0`: Tests encoding of `bbb_352x288_420p_30fps_32frames.yuv` (352x288, 30fps)
  - `EncodeTest/1`: Tests encoding of `football_qvga.yuv` (320x240, 30fps)

### Build Requirements
From `tests/README.md` and `CMakeLists.txt`:
1. CMake 3.9.1 or above
2. Clang compiler
3. Build with `-DENABLE_TESTS=1` flag to enable test compilation
4. GoogleTest dependency (automatically fetched via ExternalProject)
5. Test media files from Google's storage

### Test Execution Requirements
- Media files must be downloaded from: `https://dl.google.com/android-unittest/media/external/libavc/tests/AvcTestRes-1.0.zip`
- Tests require `-P <path>` argument pointing to extracted media directory
- Test executable: `AvcEncTest`

## test.sh Implementation Strategy

### Key Design Decisions

1. **Separate Build Directory**
   - Use `/tmp/libavc_test_build` to avoid conflicts with fuzzer builds
   - Clean build ensures no state pollution between runs

2. **CMake Configuration**
   - Enable tests: `-DENABLE_TESTS=1`
   - Use clang compiler (consistent with OSS-Fuzz)
   - Debug build for better error messages

3. **Media File Handling**
   - Download test resources at runtime (not in Docker image)
   - Extract to build directory
   - Verify extraction succeeded before running tests

4. **Test Execution**
   - Run `AvcEncTest` with `-P` flag pointing to media directory
   - GoogleTest will discover and run all parameterized tests

### Script Flow

```bash
1. Create clean test build directory (/tmp/libavc_test_build)
2. Configure CMake with -DENABLE_TESTS=1
3. Build AvcEncTest target
4. Verify binary exists
5. Download AvcTestRes-1.0.zip
6. Extract test media files
7. Run ./AvcEncTest -P <media_dir>/
8. Report success/failure
```

### Execution Environment
- **Container WORKDIR**: `/src/libavc` (project root)
- **test.sh location**: `/src/test.sh` in container
- **Execution context**: Script runs from WORKDIR via `bash /src/test.sh`

## Test Results

### First Execution (Success)
```
[==========] Running 2 tests from 1 test suite.
[----------] 2 tests from EncodeTest/AvcEncTest
[ RUN      ] EncodeTest/AvcEncTest.EncodeTest/0
[       OK ] EncodeTest/AvcEncTest.EncodeTest/0 (36 ms)
[ RUN      ] EncodeTest/AvcEncTest.EncodeTest/1
[       OK ] EncodeTest/AvcEncTest.EncodeTest/1 (81 ms)
[----------] 2 tests from EncodeTest/AvcEncTest (118 ms total)

[  PASSED  ] 2 tests.
```

**Status**: ✅ All tests passed on first attempt

## Code Coverage

The tests exercise the following components:
- **Encoder initialization** (`ih264e_api_function`)
- **Frame encoding** (processing YUV input frames)
- **Bitstream generation** (encoding to H.264 format)
- **Memory management** (codec context allocation)
- **Configuration** (QP, frame rate, dimensions, GOP)

The test suite validates the core encoder functionality with real video data, making it suitable for detecting regressions from code mutations.

## Maintenance Notes

- Test media files are ~10MB (downloaded at runtime)
- Tests complete in ~120ms
- No special environment variables required
- Tests are deterministic and stable
