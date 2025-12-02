#!/bin/bash -e
# Test script for mongoose
# This script compiles and runs the unit tests for the Mongoose web server library

# Mongoose has comprehensive unit tests in test/unit_test.c
# The Makefile target "test" compiles mongoose.c, test/unit_test.c, and test/packed_fs.c

cd "$SRC/cp-c-mongoose-src"

# First, generate test/packed_fs.c (required dependency)
echo "Generating packed_fs.c..."
$CC $CFLAGS test/pack.c -o pack
./pack Makefile src/ssi.h test/fuzz.c test/data/a.txt test/data/range.txt > test/packed_fs.c

# Build the unit test binary
echo "Building unit tests..."
$CC mongoose.c test/unit_test.c test/packed_fs.c \
    $CFLAGS \
    -DMG_MAX_HTTP_HEADERS=7 \
    -DMG_ENABLE_LINES \
    -DMG_ENABLE_PACKED_FS=1 \
    -DMG_ENABLE_SSI=1 \
    -DMG_ENABLE_IPV6=1 \
    -I. \
    -Isrc \
    -o unit_test

# Run the unit tests
echo "Running unit tests..."
./unit_test

echo "All tests passed!"
