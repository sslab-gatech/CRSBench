#!/bin/bash
set -ex

cd "${SRC}/pcre2"

# Generate configure script if it doesn't exist
if [ ! -f configure ]; then
    ./autogen.sh
fi

# Configure for testing with JIT but without fuzzer-specific limits
if [ ! -f Makefile ]; then
    ./configure --enable-jit
fi

# Build
make -j$(nproc)

# Run full test suite
make check