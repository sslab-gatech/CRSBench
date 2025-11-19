#!/bin/bash
set -e

cd $SRC/lcms
./configure --enable-shared=no
make clean
make -j$(nproc) all
cd testbed
make testcms -j$(nproc)
./testcms
