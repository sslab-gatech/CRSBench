#!/bin/bash
set -e

# Test strategy for sanity-stress-test-full-01:
# This project has no traditional unit tests, only fuzzing harnesses
# We'll compile a simple test program that exercises utils.c functions

# Already in $SRC/cp-user-stress-test-src

# Create a simple test program to exercise utils.c
cat > test_utils.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "utils.h"

int test_buffer_create_destroy() {
    buffer_t *buf = buffer_create(100);
    if (buf == NULL) {
        fprintf(stderr, "FAIL: buffer_create returned NULL\n");
        return 1;
    }
    buffer_destroy(buf);
    printf("PASS: test_buffer_create_destroy\n");
    return 0;
}

int test_buffer_write_read() {
    buffer_t *buf = buffer_create(100);
    if (buf == NULL) {
        fprintf(stderr, "FAIL: buffer_create returned NULL\n");
        return 1;
    }

    // Write and read a value
    buffer_write(buf, 50, 'A');
    char value = buffer_read(buf, 50);
    if (value != 'A') {
        fprintf(stderr, "FAIL: expected 'A', got '%c'\n", value);
        buffer_destroy(buf);
        return 1;
    }

    // Test boundary - reading at size should return 0
    char boundary = buffer_read(buf, 100);
    if (boundary != 0) {
        fprintf(stderr, "FAIL: expected boundary read to return 0\n");
        buffer_destroy(buf);
        return 1;
    }

    buffer_destroy(buf);
    printf("PASS: test_buffer_write_read\n");
    return 0;
}

int test_buffer_boundary_write() {
    buffer_t *buf = buffer_create(100);
    if (buf == NULL) {
        fprintf(stderr, "FAIL: buffer_create returned NULL\n");
        return 1;
    }

    // Write at valid index
    buffer_write(buf, 99, 'Z');
    char value = buffer_read(buf, 99);
    if (value != 'Z') {
        fprintf(stderr, "FAIL: expected 'Z', got '%c'\n", value);
        buffer_destroy(buf);
        return 1;
    }

    // Write beyond size should be safe (no crash)
    buffer_write(buf, 101, 'X');

    buffer_destroy(buf);
    printf("PASS: test_buffer_boundary_write\n");
    return 0;
}

int main() {
    int failures = 0;

    printf("Running utils.c tests...\n");

    failures += test_buffer_create_destroy();
    failures += test_buffer_write_read();
    failures += test_buffer_boundary_write();

    if (failures == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
}
EOF

# Compile the test program
gcc -o test_utils test_utils.c utils.c -I.

# Run the tests
./test_utils
