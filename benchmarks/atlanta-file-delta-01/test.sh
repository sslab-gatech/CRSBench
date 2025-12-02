#!/bin/bash
set -ex

cd $SRC/file
rm -f tests/multiple.*
sed -i '/multiple/d' tests/Makefile.am
autoreconf -f -i
# make distclean
./configure --disable-silent-rules
make -j4
make -C tests check
