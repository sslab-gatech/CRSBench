# test.sh Rationale for atlanta-freetype2-delta-01

## Summary

This test.sh script validates FreeType2's trigonometric functions by building the library from source and running its existing unit tests.

## Test Approach

### Priority Selection
Following the test priority guidelines:
1. **FIRST CHOICE**: Use existing unit tests ✓ (selected)
2. SECOND: Integration/functional tests
3. LAST RESORT: Smoke tests

### Chosen Test
- **Test Program**: `src/tools/test_trig.c`
- **Test Type**: Unit test (existing in FreeType2 codebase)
- **Functions Tested**:
  - `FT_Sin()` - Sine function
  - `FT_Cos()` - Cosine function
  - `FT_Tan()` - Tangent function
  - `FT_Atan2()` - Arc tangent function
  - `FT_Vector_Unit()` - Unit vector computation
  - `FT_Vector_Length()` - Vector length calculation
  - `FT_Vector_Rotate()` - Vector rotation

## Build Process

### Environment
- Build system: Autotools (./autogen.sh, ./configure, make)
- Reason: Meson not available in container, but autotools is
- Compiler: clang (default in OSS-Fuzz environment)

### Build Steps
1. Run `autogen.sh` to generate configure script
2. Run `./configure` to set up build configuration
3. Run `make` to build libfreetype library
4. Verify build artifacts exist (`objs/.libs/libfreetype.{a,so}`)

### Output Suppression
Build output is redirected to `/dev/null` to prevent token limit issues during MCP testing.

## Test Compilation

### Compilation Command
```bash
clang -I./include -Wno-error=implicit-int -o test_trig src/tools/test_trig.c -L./objs/.libs -lfreetype -lm
```

### Key Flags
- `-I./include`: Include FreeType headers
- `-Wno-error=implicit-int`: Allow implicit int warning (test source has `static error = 0;` without type)
- `-L./objs/.libs`: Link directory for libfreetype
- `-lfreetype -lm`: Link against FreeType and math libraries

### Why Not Use freetype-config?
freetype-config provides `-lfreetype` but doesn't include the correct library search path for the just-built library in `./objs/.libs/`. We need `-L./objs/.libs` to find the library.

## Test Execution

### Runtime Environment
```bash
LD_LIBRARY_PATH=./objs/.libs:$LD_LIBRARY_PATH ./test_trig
```

### Success Criteria
The test prints "trigonometry test ok !" when all trigonometric functions pass their validation checks.

### Validation Method
```bash
if ./test_trig 2>&1 | grep -q "trigonometry test ok"; then
    # Test passed
fi
```

## Why This Test is Appropriate

1. **Functionality Testing**: Tests actual trigonometric computations, not just build success
2. **Regression Detection**: Will catch bugs in FT_Sin, FT_Cos, FT_Tan, FT_Atan2, etc.
3. **Existing Test**: Uses project's own unit test (not a synthetic smoke test)
4. **Comprehensive**: Tests multiple related functions in the trigonometry module
5. **Deterministic**: Produces predictable output that can be validated

## Alternative Tests Considered

### test_bbox.c (Rejected)
- **Issue**: Missing function declarations (`FT_Outline_Get_CBox`)
- **Reason**: Would require additional header includes or source modifications
- **Decision**: Skip in favor of working test_trig.c

### Meson Tests (Rejected)
- **Issue**: Meson build system not available in OSS-Fuzz container
- **Reason**: Container only has autotools installed
- **Decision**: Use autotools build with manual test compilation

## Bad Patch Strategy

### Target Function
`FT_Cos()` in `src/base/fttrigon.c` (lines 296-305)

### Mutation Type
**HIGH PRIORITY**: Dummy return value
- Replace correct cosine computation with `return 0;`
- This will cause trigonometry test to fail validation checks
- Compiles successfully but produces incorrect results

### Expected Behavior
- **Without Patch**: test.sh passes (returns 0)
- **With Patch**: test.sh fails (trigonometry test detects incorrect cosine values)

## Verification

The bad_patch.diff should be verified using:
```bash
mcp__crsbench__mcp_verify_bad_patch atlanta-freetype2-delta-01 bad_patch.diff
```

This will:
1. Apply bad_patch.diff to the project source
2. Run test.sh
3. Verify that test.sh fails (exit code != 0)
4. Restore project source to original state
