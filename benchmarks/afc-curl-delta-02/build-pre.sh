#!/bin/bash -eu
# Copyright 2016 Google Inc.
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
#
# build-pre.sh: Pre-patch build script for incremental build support
#
# This script performs a complete clean build before any patches are applied.
# It installs all dependencies and performs the initial compilation of curl
# and the fuzzer infrastructure. After running this script, a Docker image
# snapshot should be saved for reuse.
#
################################################################################

echo "[build-pre.sh] Starting pre-patch build process..."

# Navigate to curl_fuzzer directory
pushd $SRC/curl_fuzzer

# Save off the current folder as the build root
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

# Source the fuzz targets configuration
. ${SCRIPTDIR}/fuzz_targets

# Set optimization level to -O0 to prevent bugs from being optimized out
export CFLAGS="$CFLAGS -O0"
export CXXFLAGS="$CXXFLAGS -O0"

echo "[build-pre.sh] Build configuration:"
echo "  BUILD_ROOT: $BUILD_ROOT"
echo "  SRC: ${SRC:-undefined}"
echo "  CC: $CC"
echo "  CXX: $CXX"
echo "  LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "  CFLAGS: $CFLAGS"
echo "  CXXFLAGS: $CXXFLAGS"
echo "  ARCHITECTURE: $ARCHITECTURE"
echo "  FUZZ_TARGETS: $FUZZ_TARGETS"

# Enable parallel builds
export MAKEFLAGS+="-j$(nproc)"

# Create installation directory for curl
export INSTALLDIR=/src/curl_install
mkdir -p ${INSTALLDIR}

echo "[build-pre.sh] Installing system dependencies..."
# Install system dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential autoconf automake libtool pkg-config \
  zlib1g-dev libssl-dev libnghttp2-dev clang lld

echo "[build-pre.sh] Building and installing curl..."
# Build and install curl
${SCRIPTDIR}/install_curl.sh /src/curl ${INSTALLDIR}

echo "[build-pre.sh] Compiling fuzzer infrastructure..."
# Compile the fuzzer
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR}

echo "[build-pre.sh] Creating seed corpus..."
# Create the seed corpus zip file
make zip

echo "[build-pre.sh] Copying initial outputs..."
# Copy options files to output directory
cp ${SRC}/*.options ${OUT}/

# Copy the fuzzers over
for TARGET in $FUZZ_TARGETS
do
  cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
done

# Copy dictionary and options files to $OUT
cp -v ossconfig/*.dict ossconfig/*.options $OUT/

# Add timeout configuration
echo -e "\ntimeout_exitcode=0\n" >> ${OUT}/curl_fuzzer.options

popd

echo "[build-pre.sh] Pre-patch build completed successfully!"
echo "[build-pre.sh] Snapshot can now be saved for incremental builds."
