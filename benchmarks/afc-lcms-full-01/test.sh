#!/bin/bash
set -ex

# Conditional configure
if [ ! -f Makefile ]; then
    ./configure --enable-shared=no
fi
make -j$(nproc) all

cd testbed
make testcms -j$(nproc)
./testcms
