#!/bin/bash
set -e

# test.sh for atlanta-freetype2-delta-01
# This script builds FreeType2 from scratch and runs its unit tests

echo "[test.sh] Starting FreeType2 build and test..."

# Build the project using autotools
echo "[test.sh] Running autogen.sh..."
./autogen.sh > /dev/null 2>&1

echo "[test.sh] Configuring FreeType2..."
./configure > /dev/null 2>&1

echo "[test.sh] Building FreeType2 library..."
make -j$(nproc) > /dev/null 2>&1

echo "[test.sh] Verifying build artifacts..."
if [ ! -f "objs/.libs/libfreetype.a" ] && [ ! -f "objs/.libs/libfreetype.so" ]; then
    echo "[test.sh] ERROR: FreeType2 library was not built successfully"
    exit 1
fi

echo "[test.sh] Build completed successfully!"

# Build and run unit tests from src/tools/
echo "[test.sh] Building and running unit tests..."

# Set compiler if not already set
CC=${CC:-clang}

# Test: Trigonometry functions test
# This test validates FreeType's trigonometric functions (FT_Sin, FT_Cos, FT_Tan, FT_Atan2, etc.)
echo "[test.sh] Compiling trigonometry test..."
$CC -I./include -Wno-error=implicit-int -o test_trig src/tools/test_trig.c -L./objs/.libs -lfreetype -lm 2>/dev/null

echo "[test.sh] Running trigonometry test..."
if LD_LIBRARY_PATH=./objs/.libs:$LD_LIBRARY_PATH ./test_trig 2>&1 | grep -q "trigonometry test ok"; then
    echo "[test.sh] Trigonometry test PASSED - all trigonometric functions working correctly!"
else
    echo "[test.sh] ERROR: Trigonometry test FAILED - trigonometric functions not working correctly"
    exit 1
fi

echo "[test.sh] All tests passed successfully!"
