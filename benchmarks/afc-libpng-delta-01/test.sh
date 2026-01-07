#!/bin/bash
set -ex

# Already in $SRC/libpng

# Build (only configure on first run)
if [ ! -f Makefile ]; then
    ./configure
fi
make -j$(nproc)
make test
