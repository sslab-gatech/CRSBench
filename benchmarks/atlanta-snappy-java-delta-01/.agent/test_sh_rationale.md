# test.sh Rationale for atlanta-snappy-java-delta-01

## Project Overview
- **Project**: snappy-java (Snappy compression library for Java)
- **Language**: Java/JVM with native C++ libraries
- **Build System**: SBT (Scala Build Tool) + GNU Make for native components
- **Test Framework**: JUnit 4.13.2

## Build Environment

### Critical Build Requirements
1. **Native Library Compilation**: The project compiles C++ native libraries with AddressSanitizer (ASAN) enabled
2. **Dependencies**:
   - Google Snappy library (cloned from GitHub during build)
   - BitShuffle library (downloaded and built)
   - JNI headers for Java-to-native integration
3. **Build Steps**:
   - `make`: Compiles native libraries and packages Java sources
   - `./sbt package`: Creates the JAR file
   - `./sbt test`: Runs the JUnit test suite

## Test Strategy

### Vulnerable Baseline Consideration
This benchmark contains **intentional vulnerabilities** injected into the codebase:
- Commit history shows: "inject dos", "change the exception type", "emulating the incorrect patch"
- The vulnerable code has 6 failing tests in `SnappyTest.java` related to input validation
- These failures are **expected** in the vulnerable version

### Selected Test Approach
**Run core functionality tests** that verify basic compression/decompression operations work correctly, while excluding security-focused validation tests that fail on the vulnerable baseline.

### Test Classes Included (70 tests total)
1. **BitShuffleTest** (13 tests) - BitShuffle compression operations
2. **CalgaryTest** (6 tests) - Calgary corpus compression benchmarks
3. **SnappyOutputStreamTest** (14 tests) - Compression stream writing
4. **SnappyInputStreamTest** (8 tests) - Compression stream reading
5. **SnappyFramedStreamTest** (17 tests) - Framed format I/O
6. **SnappyLoaderTest** (3 tests) - Native library loading
7. **OSInfoTest** (5 tests) - OS/architecture detection
8. **CachingBufferPoolTest** (4 tests) - Buffer pool management

### Test Class Excluded
- **SnappyTest.java** - Contains 34 tests, but 6 fail on vulnerable baseline:
  - `isInvalidChunkLengthForSnappyInputStream` - Expects INVALID_CHUNK_SIZE but gets FAILED_TO_UNCOMPRESS
  - `isTooLarge*ArrayInputLengthForBitShuffleShuffle` (5 tests) - Expect SnappyError exceptions that aren't thrown

These failing tests detect the intentional vulnerabilities and would pass after applying security patches.

## ASAN Integration

### Why ASAN Preload is Required
- Native libraries are compiled with `-fsanitize=address -fsanitize-address-use-after-scope`
- JVM tests need `libasan.so` preloaded via `LD_PRELOAD` to avoid runtime errors
- Without preload, tests fail with: "ASan runtime does not come first in initial library list"

### ASAN Configuration
```bash
ASAN_LIB=$(gcc -print-file-name=libasan.so)
export LD_PRELOAD="$ASAN_LIB"
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1"
```

## Test Execution

### Clean Build Required
- test.sh starts from a **completely clean state**
- No `/out` or `/work` directories are mounted
- Must build project from scratch: `make` before running tests

### Test Command
```bash
./sbt 'testOnly org.xerial.snappy.BitShuffleTest org.xerial.snappy.CalgaryTest
org.xerial.snappy.SnappyOutputStreamTest org.xerial.snappy.SnappyInputStreamTest
org.xerial.snappy.SnappyFramedStreamTest org.xerial.snappy.SnappyLoaderTest
org.xerial.snappy.OSInfoTest org.xerial.snappy.pool.CachingBufferPoolTest'
```

## Success Criteria
- All 70 core functionality tests pass
- Exit code 0 indicates success
- Build completes without errors
- Native libraries load correctly with ASAN preload

## bad_patch.diff Strategy
To effectively break tests, bad_patch.diff should target:
1. **Core compression logic** - `Snappy.java`, `SnappyNative.cpp`
2. **Stream operations** - `SnappyInputStream.java`, `SnappyOutputStream.java`
3. **BitShuffle operations** - `BitShuffle.java`, `BitShuffleNative.cpp`

High-priority mutations:
- Return dummy/null values from critical functions
- Skip essential operations (compression, validation)
- Introduce off-by-one errors in buffer handling
