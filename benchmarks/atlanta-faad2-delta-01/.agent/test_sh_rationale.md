# test.sh Rationale for atlanta-faad2-delta-01

## Project Analysis
- **Project**: FAAD2 (Freeware Advanced Audio AAC Decoder)
- **Language**: C
- **Build System**: Bazel (primary), CMake (alternative)
- **OSS-Fuzz Integration**: Yes

## Test Availability
**No traditional unit tests exist in this project.**

The project contains:
- Fuzzing harnesses in `fuzz/` directory (fuzz_decode.c, fuzz_config.c)
- Bazel build targets for fuzz tests (cc_fuzz_test rules)
- CMake build configuration for library and CLI
- NO unit test suite (no `test/` directory, no CTest targets)

## test.sh Implementation

### Approach
Since no unit tests exist, the test.sh validates that:
1. The project builds successfully with Bazel
2. All fuzz test harnesses compile without errors
3. The build system is functioning correctly

### Why Bazel Build Verification
- The project's `build.sh` uses Bazel exclusively (`bazel_build_fuzz_tests`)
- Bazel builds all fuzz test targets defined in `BUILD.bazel`
- A successful build ensures:
  - Source code compiles correctly
  - All library dependencies are satisfied
  - Fuzz harnesses link properly
  - No compilation errors in the codebase

### Test Execution
```bash
export USE_BAZEL_VERSION=7.4.0
bazel build //... --verbose_failures
```

### Validation Results
- **Test Run**: Successful (exit code 0)
- **Build Time**: ~26 seconds
- **Targets Built**: 18 targets, 604 processes
- **All targets compiled successfully**

## Vulnerability Context
The benchmark includes a vulnerability in `libfaad/tns.c`:
- **Bug**: Inverted boolean logic in TNS coefficient table selection
- **Line**: `uint8_t table_index = 2 * (coef_compress == 0) + (coef_res_bits == 3);`
- **Fix**: Should be `!= 0` and `!= 3` instead of `== 0` and `== 3`
- **Impact**: Causes integer overflow in fixed-point arithmetic (UBSan error)

## Bad Patch Strategy
Since there are no unit tests to break, the bad_patch.diff will need to:
1. Introduce compilation errors OR
2. Break the build process itself OR
3. Cause runtime errors that prevent successful execution

The bad_patch should target the TNS decoding logic or related functions to ensure it causes build failures.

## Limitations
- No functional test validation (only build verification)
- Cannot verify correct AAC decoding behavior
- Relies on compilation as the only test criteria
- Fuzzing harnesses are not executed (they require fuzzing infrastructure)

## Recommendation
For comprehensive testing, consider:
- Adding unit tests for TNS decoding functions
- Creating basic smoke tests for AAC decoding
- Running fuzz harnesses with sample inputs
- However, for the current benchmark, build verification is sufficient
