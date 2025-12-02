# bad_patch.diff Rationale for atlanta-sleuthkit-delta-01

## Overview

The bad_patch.diff introduces **HIGH PRIORITY** mutations that will cause the sleuthkit build to fail. These mutations target core memory management and file system I/O functions.

## Mutations

### 1. Memory Management Bug in `tsk_realloc()` (tsk/base/mymalloc.c)

**Type**: Uninitialized variable use

**Change**:
```c
// Original
void *tmpPtr = realloc(ptr, len);
if (tmpPtr == 0) {
    // error handling
}

// Mutated
void *tmpPtr; {  // tmpPtr declared but never initialized
    ptr = tmpPtr;  // Use uninitialized tmpPtr!
}
```

**Impact**:
- `tmpPtr` is declared but never assigned a value (removed `= realloc(ptr, len)`)
- The code then assigns uninitialized `tmpPtr` to `ptr`
- This is undefined behavior and will cause:
  - Compiler warnings about uninitialized variable use
  - Runtime crashes when `tsk_realloc()` is called
  - Memory corruption

**Why this breaks tests**:
- `tsk_realloc()` is used throughout the codebase
- Using uninitialized pointers will cause segmentation faults
- The build may succeed with warnings, but runtime will fail

### 2. Function Signature Mismatch in `tsk_fs_read()` (tsk/fs/fs_io.c)

**Type**: Removed function parameter

**Change**:
```c
// Original
ssize_t
tsk_fs_read(TSK_FS_INFO * a_fs, TSK_OFF_T a_off, char *a_buf, size_t a_len)

// Mutated
ssize_t
tsk_fs_read(TSK_FS_INFO * a_fs, TSK_OFF_T a_off, char *a_buf)
```

**Impact**:
- Removed the `size_t a_len` parameter from function signature
- Function body still references `a_len` on line 92: `return tsk_fs_read_decrypt(a_fs, a_off, a_buf, a_len, 0);`
- This will cause **IMMEDIATE COMPILATION FAILURE**:
  - "error: 'a_len' undeclared (first use in this function)"
  - Function signature doesn't match header declaration in `tsk/fs/tsk_fs.h`
  - All call sites (100+ locations) pass 4 arguments but function only accepts 3

**Why this breaks tests**:
- This mutation causes a **compilation error**
- The `make` command in test.sh will fail
- Libraries will not be built
- Test verification will fail because core libraries won't exist

### 3. Error Handling Removal in `tsk_malloc()` (tsk/base/mymalloc.c)

**Type**: Removed error handling

**Change**:
```c
// Original
if ((ptr = calloc(len, 1)) == 0) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
    tsk_error_set_errstr("tsk_malloc: %s", strerror(errno));
}

// Mutated
ptr = calloc(len, 1);
```

**Impact**:
- Removed NULL pointer check after `calloc()`
- If memory allocation fails, the error state is not set
- Calling code may not detect allocation failure
- This will compile successfully but causes **logic errors**

## Expected Test Behavior

When bad_patch.diff is applied:

1. **Build Phase**: `make` will fail during compilation of `tsk/fs/fs_io.c`
   - Error: `'a_len' undeclared` in `tsk_fs_read()`
   - Compilation will stop before linking

2. **Test Phase**: test.sh will fail when checking for library existence
   - `tsk/.libs/libtskfs.a` will not exist (filesystem library failed to build)
   - Exit code: 1 (test failure)

## Mutation Priority

Both mutations are **HIGH PRIORITY**:
- ✅ **tsk_fs_read** parameter removal: Causes immediate build failure
- ✅ **tsk_realloc** uninitialized use: Causes undefined behavior
- ✅ **tsk_malloc** error handling: Logic error

## Verification

The bad_patch.diff has been verified to:
1. Apply cleanly to the source tree
2. Cause the `tsk_fs_read` function to have an undeclared variable
3. Create function signature mismatch with header file
4. Break the build process that test.sh depends on
