#!/bin/bash
set -e
set -x

# Test script for binutils
# This script builds binutils from scratch and runs its DejaGnu test suite

# Build binutils first (test.sh runs in CLEAN environment with NO pre-built artifacts)
./configure --disable-gdb --disable-gdbserver --disable-gdbsupport \
    --disable-libdecnumber --disable-readline --disable-sim \
    --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
    --enable-targets=all

make -j$(nproc)

# Run the binutils test suite using DejaGnu
cd binutils
make check
