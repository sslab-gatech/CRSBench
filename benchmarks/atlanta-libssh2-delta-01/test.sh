#!/bin/bash
# Copyright 2024 CRSBench
# Test script for libssh2

set -e  # Exit on error
set -x  # Print commands for debugging

# This script is executed from /src/libssh2 (WORKDIR)
# The test.sh file is located at /src/test.sh

echo "=== Starting libssh2 test suite ==="

# Create build directory
BUILD_DIR="/tmp/libssh2-build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Step 1: Configure the project with CMake
echo "=== Configuring libssh2 with CMake ==="
cmake /src/libssh2 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=OFF \
    || { echo "CMake configuration failed"; exit 1; }

# Step 2: Build the library and tests
echo "=== Building libssh2 library and tests ==="
cmake --build . -j$(nproc) || { echo "Build failed"; exit 1; }

# Step 3: Run the test suite
echo "=== Running libssh2 test suite ==="
cd tests

# Run test_simple (basic functionality test)
# This test validates core SSH2 session functionality without requiring network/Docker
if [ -f ./test_simple ]; then
    echo "Running test_simple..."
    ./test_simple || { echo "test_simple failed"; exit 1; }
else
    echo "ERROR: test_simple not found"
    exit 1
fi

# Note: test_hostkey and test_auth_keyboard_info_request require Docker-in-Docker
# which is not available in this environment, so we skip them.
# test_simple provides sufficient coverage for basic functionality validation.

echo "=== All tests passed successfully ==="
exit 0
