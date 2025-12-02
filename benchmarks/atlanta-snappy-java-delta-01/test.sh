#!/bin/bash -eu
# Test script for snappy-java
# This script runs the JUnit test suite for snappy-java using SBT
#
# Note: The baseline code contains intentional vulnerabilities. Some security-focused
# unit tests will fail in the vulnerable version, which is expected. This script
# runs core functionality tests that should pass even in the vulnerable version.

set -o pipefail

# Build the project first (compile Java code and native libraries)
echo "[test.sh] Building project with make..."
make

# Find and preload libasan for native library tests
# The native library was built with -fsanitize=address, so we need to preload libasan
ASAN_LIB=$(gcc -print-file-name=libasan.so || echo "")
if [ -n "$ASAN_LIB" ] && [ -f "$ASAN_LIB" ]; then
    export LD_PRELOAD="$ASAN_LIB"
    export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1"
    echo "[test.sh] Preloading ASAN library: $ASAN_LIB"
fi

# Run core functionality tests (excluding security validation tests that fail on vulnerable version)
# These tests verify basic compression/decompression work correctly
echo "[test.sh] Running core functionality tests with SBT..."
if ./sbt 'testOnly org.xerial.snappy.BitShuffleTest org.xerial.snappy.CalgaryTest org.xerial.snappy.SnappyOutputStreamTest org.xerial.snappy.SnappyInputStreamTest org.xerial.snappy.SnappyFramedStreamTest org.xerial.snappy.SnappyLoaderTest org.xerial.snappy.OSInfoTest org.xerial.snappy.pool.CachingBufferPoolTest'; then
    echo "[test.sh] Core functionality tests passed!"
    exit 0
else
    echo "[test.sh] Core functionality tests failed!"
    exit 1
fi
