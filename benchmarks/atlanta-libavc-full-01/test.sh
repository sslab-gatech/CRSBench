#!/bin/bash -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
# Test script for libavc AvcEncTest
#
# This script runs the GoogleTest-based encoder test suite.
# The test requires media files which are downloaded from Google's storage.

set -e

echo "=== Starting libavc AvcEncTest ==="

# Create build directory for tests
TEST_BUILD_DIR="/tmp/libavc_test_build"
rm -rf "$TEST_BUILD_DIR"
mkdir -p "$TEST_BUILD_DIR"
cd "$TEST_BUILD_DIR"

echo "=== Configuring CMake with tests enabled ==="
# Configure with tests enabled
cmake /src/libavc \
  -DENABLE_TESTS=1 \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug

echo "=== Building AvcEncTest ==="
# Build the test executable
make AvcEncTest -j$(nproc)

echo "=== Checking if AvcEncTest binary was built ==="
if [ ! -f "./AvcEncTest" ]; then
  echo "ERROR: AvcEncTest binary not found!"
  exit 1
fi

echo "=== Downloading and extracting test media files ==="
# Download test media files
TEST_MEDIA_URL="https://dl.google.com/android-unittest/media/external/libavc/tests/AvcTestRes-1.0.zip"
TEST_MEDIA_ZIP="/tmp/AvcTestRes-1.0.zip"
TEST_MEDIA_DIR="$TEST_BUILD_DIR/AvcTestRes-1.0"

curl -L -o "$TEST_MEDIA_ZIP" "$TEST_MEDIA_URL"
unzip -q "$TEST_MEDIA_ZIP" -d "$TEST_BUILD_DIR"

# Verify test media files exist
if [ ! -d "$TEST_MEDIA_DIR" ]; then
  echo "ERROR: Test media directory not found after extraction!"
  exit 1
fi

echo "=== Running AvcEncTest ==="
# Run the test suite with the media files path
./AvcEncTest -P "$TEST_MEDIA_DIR/"

echo "=== AvcEncTest completed successfully ==="
