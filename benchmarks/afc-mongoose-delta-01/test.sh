#!/bin/bash
set -ex

# Clear some variables set by other scripts
unset CC
unset CXX
unset CFLAGS
unset CXXFLAGS
unset RUSTFLAGS

# Turn off IPv6 tests
export IPV6=0

cd test
make test