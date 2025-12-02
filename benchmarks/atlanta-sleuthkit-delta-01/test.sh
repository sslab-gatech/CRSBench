#!/bin/bash
set -e

# test.sh for atlanta-sleuthkit-delta-01
# Purpose: Build the project and run smoke tests to verify functionality

echo "[test.sh] Building sleuthkit from source..."

# Build the project from scratch
./bootstrap
./configure --enable-static --disable-shared --disable-java --without-afflib --without-libewf --without-libvhdi --without-libvmdk
make -j$(nproc)

echo "[test.sh] Build completed successfully"

# Run smoke tests - verify critical libraries were built
echo "[test.sh] Running smoke tests..."

# Check that core libraries exist
if [ ! -f "tsk/.libs/libtsk.a" ]; then
    echo "[test.sh] Error: libtsk.a not found"
    exit 1
fi

if [ ! -f "tsk/base/.libs/libtskbase.a" ]; then
    echo "[test.sh] Error: libtskbase.a not found"
    exit 1
fi

if [ ! -f "tsk/fs/.libs/libtskfs.a" ]; then
    echo "[test.sh] Error: libtskfs.a not found"
    exit 1
fi

echo "[test.sh] All smoke tests passed - core libraries built successfully"
