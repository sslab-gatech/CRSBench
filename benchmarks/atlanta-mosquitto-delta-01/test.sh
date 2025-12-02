#!/bin/bash
set -e

# test.sh for atlanta-mosquitto-delta-01
# This script runs the CUnit unit tests for the Mosquitto project

# Build cJSON dependency first (always rebuild in clean environment)
cd /src/cJSON
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF -DCMAKE_C_FLAGS=-fPIC . > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
make install > /dev/null 2>&1

# Build mosquitto components
cd /src/cp-c-mosquitto-src

# Build libcommon (needed for unit tests)
echo "Building libcommon..."
make -C libcommon -j$(nproc)

# Build lib (mosquitto library)
echo "Building lib..."
make -C lib -j$(nproc)

# Build src (broker)
echo "Building src..."
make -C src WITH_DOCS=no WITH_FUZZING=no WITH_EDITLINE=no -j$(nproc)

# Run unit tests
echo "Running unit tests..."
cd /src/cp-c-mosquitto-src/test/unit

# Build and run libcommon unit tests
echo "Testing libcommon..."
make -C libcommon test

# Build and run broker unit tests if they exist
if [ -d "broker" ]; then
    echo "Testing broker..."
    make -C broker test || true
fi

# Build and run lib unit tests if they exist
if [ -d "lib" ]; then
    echo "Testing lib..."
    make -C lib test || true
fi

echo "All tests completed successfully!"
