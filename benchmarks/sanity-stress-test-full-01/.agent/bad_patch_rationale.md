# bad_patch.diff Rationale for sanity-stress-test-full-01

## Mutation Strategy

Applied **HIGH PRIORITY** mutations to `utils.c` that break core buffer functionality.

## Mutations Applied

### Mutation 1: Buffer Size Set to Zero
```c
// Original:
buf->size = size;

// Mutated:
buf->size = 0;
```

**Impact**:
- All buffer operations think the buffer has size 0
- Write operations will fail boundary checks
- Read operations will return 0 for all indices

### Mutation 2: Broken Boundary Check
```c
// Original:
if (index >= buf->size) {
    return 0;
}

// Mutated:
if (index >= buf->size + 1000) {
    return 0;
}
```

**Impact**:
- Boundary check is ineffective (offset by 1000)
- Combined with Mutation 1 (size=0), reads will access uninitialized memory
- Causes test failures when reading written values

## Verification Results

✅ **VALID**: bad_patch.diff successfully breaks test.sh

### Test Failures Observed
```
Running utils.c tests...
PASS: test_buffer_create_destroy
FAIL: expected 'A', got '\0'
FAIL: expected 'Z', got '\0'
2 test(s) failed
```

### Why Tests Failed
1. **test_buffer_write_read**:
   - Writes 'A' to index 50
   - Reads back '\0' instead because boundary check allows access but data is wrong

2. **test_buffer_boundary_write**:
   - Writes 'Z' to index 99
   - Reads back '\0' instead for same reason

## Mutation Quality

**Priority Level**: HIGH
- Uses dummy/broken values (size=0)
- Breaks core functionality naturally
- No need for overfitting in test.sh
- Existing tests catch the bugs correctly
