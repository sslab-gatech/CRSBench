#!/bin/bash
set -ex

export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only"
export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -stdlib=libc++"
export CC=clang
export CXX=clang++

# Build cJSON dependency (only configure once)
CJSON_BUILD="$SRC/cJSON_test_build"
mkdir -p "$CJSON_BUILD"
cd "$CJSON_BUILD"

if [ ! -f Makefile ]; then
    cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF -DCMAKE_C_FLAGS=-fPIC "$SRC/cJSON"
fi
make -j$(nproc)
make install

# Build mosquitto components
cd "$SRC/cp-c-mosquitto-src"

make -j$(nproc) WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_EDITLINE=no

# Run unit tests
echo "Running unit tests..."
cd "$SRC/cp-c-mosquitto-src/test/unit"

make test

echo "All tests completed successfully!"
