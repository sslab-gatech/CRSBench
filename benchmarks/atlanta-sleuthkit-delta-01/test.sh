#!/bin/bash
set -ex

# Already in $SRC/cp-c-sleuthkit

# Build (only configure on first run)
if [ ! -f Makefile ]; then
    ./bootstrap
    ./configure --enable-static --disable-shared --disable-java --without-afflib --without-libewf --without-libvhdi --without-libvmdk
fi
make -j$(nproc)

# Run tests
make -k check || true
