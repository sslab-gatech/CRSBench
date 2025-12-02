# bad_patch.diff Rationale for atlanta-netty-delta-01

## Overview
The bad_patch.diff introduces three targeted bugs into the Netty buffer module that break existing unit tests while maintaining compilation success.

## Mutations Applied

### 1. ByteBufUtil.swapInt() - Removed Byte Reversal
**Location**: `buffer/src/main/java/io/netty/buffer/ByteBufUtil.java:651`

**Original Code**:
```java
public static int swapInt(int value) {
    return Integer.reverseBytes(value);
}
```

**Mutated Code**:
```java
public static int swapInt(int value) {
    // BUG: Return value without byte reversal
    return value;
}
```

**Impact**:
- This method is used for endianness conversion (big-endian ↔ little-endian)
- Used by `hashCode()` method for little-endian buffers
- Breaks tests that verify proper endianness handling
- Multiple tests in ByteBufUtilTest depend on correct byte swapping

**Tests Affected**:
- Tests verifying hashCode calculations for little-endian buffers
- Tests checking byte order conversions
- Any test using swapInt indirectly through other utility methods

### 2. ByteBufUtil.hashCode() - Forced Wrong Code Path
**Location**: `buffer/src/main/java/io/netty/buffer/ByteBufUtil.java:215`

**Original Code**:
```java
if (buffer.order() == ByteOrder.BIG_ENDIAN) {
    for (int i = intCount; i > 0; i --) {
        hashCode = 31 * hashCode + buffer.getInt(arrayIndex);
        arrayIndex += 4;
    }
}
```

**Mutated Code**:
```java
// BUG: Always use little-endian path regardless of buffer order
if (false) {
    for (int i = intCount; i > 0; i --) {
        hashCode = 31 * hashCode + buffer.getInt(arrayIndex);
        arrayIndex += 4;
    }
}
```

**Impact**:
- Forces hashCode calculation to always use the little-endian path
- Big-endian buffers will get incorrect hash codes
- Breaks tests that verify hashCode for big-endian buffers
- Combined with mutation #1, causes cascading failures

**Tests Affected**:
- Tests verifying buffer equality and hashing
- Tests checking hashCode consistency
- ByteBufUtilTest has extensive hashCode verification

### 3. EmptyByteBuf.capacity() - Non-Zero Capacity for Empty Buffer
**Location**: `buffer/src/main/java/io/netty/buffer/EmptyByteBuf.java:75`

**Original Code**:
```java
@Override
public int capacity() {
    return 0;
}
```

**Mutated Code**:
```java
@Override
public int capacity() {
    // BUG: Return non-zero capacity for empty buffer
    return 1;
}
```

**Impact**:
- EmptyByteBuf is designed to have zero capacity by definition
- Many tests explicitly check that capacity() returns 0
- Breaks contract of EmptyByteBuf class
- Affects all 9 tests in EmptyByteBufTest

**Tests Affected**:
- `EmptyByteBufTest.testIsWritable()` - checks buffer is not writable
- `EmptyByteBufTest.testIsReadable()` - checks buffer is not readable
- `EmptyByteBufTest.testArray()` - verifies empty array properties
- Other tests that depend on capacity being 0

## Mutation Strategy: HIGH PRIORITY

All three mutations are **HIGH PRIORITY** mutations:

1. **Dummy Return Values**:
   - `swapInt()` returns input without processing
   - `capacity()` returns wrong constant value

2. **Conditional Skipping**:
   - `hashCode()` forces wrong code path with `if (false)`

3. **Guaranteed Test Failures**:
   - Each mutation directly breaks tested functionality
   - Tests explicitly verify the correct behavior
   - No way for tests to pass with these mutations

## Verification Result

✅ **VERIFIED**: The bad_patch.diff successfully causes test.sh to fail

**Verification Output**:
- Patch applied successfully
- test.sh exit code: 1 (failure)
- Tests failed as expected
- Patch reversed successfully

## Why These Mutations Work

1. **Direct Impact**: Each mutation directly affects methods under test
2. **Type Safety**: All mutations maintain type safety and compile successfully
3. **Semantic Errors**: Introduces logic errors, not syntax errors
4. **Test Coverage**: The test suite explicitly checks the mutated behavior
5. **No Overfitting**: Mutations are in production code, not test-specific logic

## Expected Test Failures

With bad_patch applied, expect failures in:
- ByteBufUtilTest: ~20-30 tests related to hashing and byte swapping
- EmptyByteBufTest: 5-9 tests checking capacity and buffer properties
- Total expected failures: 25-40 out of 191 tests

The remaining tests may pass because they don't exercise the mutated code paths.
