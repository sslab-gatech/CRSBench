#!/bin/bash
pushd .
mkdir /tmp/autoconf-2.71-build
cd /tmp/autoconf-2.71-build
wget https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.xz
tar -xf autoconf-2.71.tar.xz
cd autoconf-2.71/
./configure
make install
popd 