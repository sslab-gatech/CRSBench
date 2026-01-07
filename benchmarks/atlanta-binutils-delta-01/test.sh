#!/bin/bash
set -ex

# Already in $SRC/cp-c-binutils-src

# Remove config.cache files to avoid "CFLAGS changed" errors
# This is needed because build.sh uses ASAN flags but test.sh doesn't
find . -name config.cache -delete 2>/dev/null || true

# Build binutils first (test.sh runs in CLEAN environment with NO pre-built artifacts)
# Only configure if not already configured
if [ ! -f Makefile ]; then
    ./configure --disable-gdb --disable-gdbserver --disable-gdbsupport \
        --disable-libdecnumber --disable-readline --disable-sim \
        --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
        --enable-targets=all
fi

make -j$(nproc)

# Run the binutils test suite using DejaGnu
cd binutils
make -k check || true
