# Test.sh Rationale for sanity-missing-vulnerabilities-full-01

## Project Overview
This benchmark is a C/C++ project with three modules containing intentional vulnerabilities:
1. **audio.c** - Stack buffer underflow in audio processing moving average filter (CPV_0)
2. **message.c** - Stack-use-after-scope due to returning pointer to local array (CPV_1)
3. **auth.cpp/user.c** - Intra-object buffer overflow in username setting (CPV_2)

## Test Strategy

### Challenge: No Pre-existing Unit Tests
The project has NO existing unit tests. The only test infrastructure is fuzzing harnesses in the `.oss-fuzz/.aixcc/` directory which use POV blobs to trigger vulnerabilities.

### Solution: Create Functional Tests
Since there are no unit tests to run, we created basic functional tests that:
1. Verify each module's basic functionality
2. Test valid input handling
3. Test invalid input handling (boundary conditions)
4. Ensure functions don't crash on normal inputs

## Test Implementation

### Test Structure
```bash
# Step 1: Recompile source files for testing
# - The build.sh creates object files with fuzzer instrumentation
# - We recompile cleanly without fuzzer instrumentation for testing
$CC $CFLAGS -c audio.c -o audio_test.o
$CC $CFLAGS -c message.c -o message_test.o
$CC $CFLAGS -c user.c -o user_test.o
$CXX $CXXFLAGS -c auth.cpp -o auth_test.o

# Step 2: Create and run test for each module
# Each test is a standalone C/C++ program that:
# - Includes the module header
# - Tests valid inputs (should succeed)
# - Tests invalid inputs (should fail gracefully)
# - Uses assertions to verify behavior
```

### Module-Specific Tests

#### 1. audio.c tests
- **Test 1**: Valid input with magic value 0xdeadbeef → should return non-NULL
- **Test 2**: Invalid magic value → should return NULL
- **Test 3**: Too small input (< 4 bytes) → should return NULL

#### 2. message.c tests
- **Test 1**: Valid message with correct header "MSGB" (0x4D534742) → should return non-NULL
- **Test 2**: Invalid header → should return NULL
- **Test 3**: Too small input (< 8 bytes) → should return NULL

Note: parse_message has a bug (returns stack memory), but tests still work since we immediately use the returned value.

#### 3. auth.cpp/user.c tests
- **Test 1**: Valid authentication with correct key 0xc0ffee → should not crash
- **Test 2**: Invalid key → should be handled gracefully
- **Test 3**: Too small input → should be handled gracefully

### Technical Details

#### Compilation Approach
- **Object files from build**: Have fuzzer instrumentation (`-fsanitize=fuzzer`) which requires `libFuzzingEngine.a`
- **Test compilation**: Recompile source without fuzzer instrumentation using standard `$CFLAGS`
- **C++ linking**: Requires `-pthread` for libc++ exception handling

#### Environment
- **Working directory**: `/src/missing-vulnerabilities` (WORKDIR)
- **test.sh location**: `/src/test.sh`
- **Execution**: `bash /src/test.sh` runs from WORKDIR

## Test Coverage
The tests cover:
- ✅ Basic functionality of each module
- ✅ Input validation (magic values, headers, size checks)
- ✅ Null pointer handling
- ✅ Boundary conditions
- ✅ Compilation and linking correctness

The tests do NOT:
- ❌ Explicitly test for vulnerabilities (that's what POVs are for)
- ❌ Test edge cases that trigger bugs
- ❌ Use sanitizers to detect memory errors

## Expected Behavior
- **Normal code**: All tests pass (functions handle valid/invalid inputs correctly)
- **With mutations**: Tests should fail if critical functionality is broken

## Notes for bad_patch.diff
Good mutation targets to break these tests:
1. **process_audio_data**: Return NULL always, skip magic check
2. **parse_message**: Return NULL always, skip header check
3. **authenticate_user**: Make it crash or skip validation
4. **min_size**: Return wrong values
5. **set_username**: Skip memcpy operation
