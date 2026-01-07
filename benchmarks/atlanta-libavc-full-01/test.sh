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
# Test script for libavc tests (Encoder + Decoder)
#
# This script runs GoogleTest-based encoder and decoder test suites.
# The decoder tests cover SVC (isvcd_parse_slice.c) and MVC (imvcd_api.c) paths
# which are modified by cpv_0 and cpv_1 patches respectively.

set -e

echo "=== Starting libavc Tests (Encoder + Decoder) ==="

# Verify Pin is available
export PIN_ROOT=/opt/pin
export BINARY_RTS=/opt/binary-rts
export PINTOOLS_RTS=$BINARY_RTS/pintools-rts
export PIN_LISTENER_DIR=$PINTOOLS_RTS/pin_listener

RTS_ON=${RTS_ON:-0}
SNAPSHOT_RTS=$(test -d $PIN_ROOT && echo 1 || echo 0) # artifact of rts_init_c.py
echo "SNAPSHOT_RTS $SNAPSHOT_RTS RTS_ON $RTS_ON"

# Already in $SRC/libavc
PROJECT_DIR="$PWD"
TEST_BUILD_DIR="/tmp/libavc_test_build"
mkdir -p "$TEST_BUILD_DIR"
cd "$TEST_BUILD_DIR"

# Clear OSS-Fuzz clang-specific flags that break test builds
# (OSS-Fuzz sets -stdlib=libc++ which causes ABI mismatch with googletest if not propagated)
unset CFLAGS CXXFLAGS LDFLAGS

# Only run cmake if not already configured
if [[ ! -f "CMakeCache.txt" ]]; then
  if [[ $SNAPSHOT_RTS -eq 1 ]]; then
    echo ""
    echo "=== Configuring CMake with Pin listener enabled (SVC + MVC enabled) ==="
    cmake $PROJECT_DIR \
      -DENABLE_TESTS=1 \
      -DENABLE_SVC=ON \
      -DENABLE_MVC=ON \
      -DENABLE_PIN_LISTENER=ON \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug
  else
    cmake $PROJECT_DIR \
      -DENABLE_TESTS=1 \
      -DENABLE_SVC=ON \
      -DENABLE_MVC=ON \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug
  fi
fi

echo ""
echo "=== Building AvcEncTest and AvcDecTest ==="
make AvcEncTest AvcDecTest -j$(nproc)

echo "=== Checking if test binaries were built ==="
if [[ ! -f "./AvcEncTest" ]]; then
  echo "ERROR: AvcEncTest binary not found!"
  exit 1
fi
if [[ ! -f "./AvcDecTest" ]]; then
  echo "ERROR: AvcDecTest binary not found!"
  exit 1
fi

echo ""
echo "=== Downloading test media files ==="
TEST_MEDIA_URL="https://dl.google.com/android-unittest/media/external/libavc/tests/AvcTestRes-1.0.zip"
TEST_MEDIA_ZIP="/tmp/AvcTestRes-1.0.zip"
TEST_MEDIA_DIR="$TEST_BUILD_DIR/AvcTestRes-1.0"

if [[ ! -d "$TEST_MEDIA_DIR" ]]; then
  curl -L -o "$TEST_MEDIA_ZIP" "$TEST_MEDIA_URL"
  unzip -q "$TEST_MEDIA_ZIP" -d "$TEST_BUILD_DIR"
fi

if [[ ! -d "$TEST_MEDIA_DIR" ]]; then
  echo "ERROR: Test media directory not found after extraction!"
  exit 1
fi

COVERAGE_BASE="/tmp/libavc_coverage"
OUTPUT_DIR="/tmp/libavc_output"

# This is the first time, we trace the unit tests
if [[ $SNAPSHOT_RTS -eq 1 && ! -d "$COVERAGE_BASE/AvcEncTest" ]]; then
  mkdir -p "$COVERAGE_BASE/AvcEncTest"
  mkdir -p "$COVERAGE_BASE/AvcDecTest"

  TEST_EXIT=0

  # Run encoder test under Pin with coverage tracing
  echo ""
  echo "=== Tracing AvcEncTest under Pin ==="
  $PIN_ROOT/pin \
    -t $PINTOOLS_RTS/obj-intel64/functrace.so \
    -runtime_dump \
    -logdir "$COVERAGE_BASE/AvcEncTest" \
    -libs 0 \
    -- ./AvcEncTest -P "$TEST_MEDIA_DIR/" || TEST_EXIT=$?

  # Run decoder test under Pin with coverage tracing
  echo ""
  echo "=== Tracing AvcDecTest under Pin ==="
  $PIN_ROOT/pin \
    -t $PINTOOLS_RTS/obj-intel64/functrace.so \
    -runtime_dump \
    -logdir "$COVERAGE_BASE/AvcDecTest" \
    -libs 0 \
    -- ./AvcDecTest -P "$TEST_MEDIA_DIR/" || TEST_EXIT=$?

  # Process Coverage Data
  echo ""
  echo "=== Coverage Data ==="
  echo "Coverage base: $COVERAGE_BASE"
  ls -la "$COVERAGE_BASE/AvcEncTest"
  ls -la "$COVERAGE_BASE/AvcDecTest"

  # Convert coverage to CSV
  echo ""
  echo "=== Converting coverage to CSV ==="
  mkdir -p "$OUTPUT_DIR"

  cd /opt/binary-rts/binaryrts/cli
  # Use COVERAGE_BASE (parent dir) since convert expects module subdirectories
  # Regex matches source file paths like /src/libavc/encoder/foo.c or /src/libavc/decoder/svc/foo.c
  poetry run binaryrts convert \
    -i "$COVERAGE_BASE" \
    --regex ".*libavc.*" \
    --repo $PROJECT_DIR \
    -o "$OUTPUT_DIR" \
    cpp

  echo ""
  echo "=== Output files ==="
  ls -la "$OUTPUT_DIR"

  # Exit with exit code
  exit $TEST_EXIT
fi


if [[ $RTS_ON -eq 1 ]]; then
  # This is subsequent test, select which ones to test
  SELECTION_DIR="/tmp/selection"
  rm -rf "$SELECTION_DIR"

  # Run binaryrts select with dirty/uncommitted changes
  PATCH=/tmp/patch.diff
  test -f $PATCH

  echo "=== Selecting unit tests (file-level) ==="
  cd /opt/binary-rts/binaryrts/cli
  # Use file-level selection because DWARF debug info for imvcd_view_decode
  # is corrupted, preventing function-level tracing of this function
  poetry run binaryrts select \
    --repo $PROJECT_DIR \
    --diff $PATCH \
    --repo-state new \
    -o "$SELECTION_DIR" \
    cpp \
    --lookup "$OUTPUT_DIR/function-lookup.csv" \
    --traces "$OUTPUT_DIR/test-function-traces.csv" \
    --file-level

  echo ""
  echo "=== Selection Results ==="
  echo "Included tests:"
  cat "$SELECTION_DIR/included.txt" || true
  echo ""
  echo "Excluded tests:"
  cat "$SELECTION_DIR/excluded.txt" || true

  # Convert included.txt to GoogleTest filter format
  export GTEST_FILTER=$(poetry run binaryrts utils filter "$SELECTION_DIR/included.txt" -f gtest 2>/dev/null)
  echo ""
  echo "GTEST_FILTER=$GTEST_FILTER"
fi


echo ""
echo "=== Running tests ==="
cd "$TEST_BUILD_DIR"

# Run encoder tests
echo ""
echo "=== Running AvcEncTest ==="
./AvcEncTest -P "$TEST_MEDIA_DIR/"

# Run decoder tests
echo ""
echo "=== Running AvcDecTest ==="
./AvcDecTest -P "$TEST_MEDIA_DIR/"

echo ""
echo "=== All tests completed ==="
