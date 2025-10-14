#!/bin/bash

set -e

cd $SRC/file
autoreconf -f -i
# make distclean
./configure --disable-silent-rules
make -j4
make -C tests check
