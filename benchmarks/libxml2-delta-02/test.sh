#!/bin/bash

./autogen.sh
./configure CFLAGS="-g" CXXFLAGS="-g" CC="clang" CXX="clang++"
make all check
