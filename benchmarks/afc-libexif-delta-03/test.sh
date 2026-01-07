#!/bin/bash
set -ex

# Already in $SRC/libexif
PROJECT_DIR="$PWD"

# Conditional autogen
[ -f configure ] || autoreconf -fi

# Out-of-tree build for tests (avoids conflict with build.sh)
BUILD_DIR="${SRC}/libexif_build_test"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure in separate directory
[ -f Makefile ] || "$PROJECT_DIR/configure"

make -j$(nproc)
make check
