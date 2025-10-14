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
# build-apply.sh: Post-patch incremental build script
#
# This script performs an incremental build after patches have been applied
# to the curl source code. It assumes build-pre.sh has already been run and
# the environment is set up. This script only rebuilds the changed components
# and should execute much faster than a clean build.
#
################################################################################

echo "[build-apply.sh] Starting incremental build after patch application..."

# Use the installation directory from pre-build
export INSTALLDIR=/src/curl_install

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

echo "[build-apply.sh] Incremental build configuration:"
echo "  BUILD_ROOT: $BUILD_ROOT"
echo "  INSTALLDIR: $INSTALLDIR"
echo "  FUZZ_TARGETS: $FUZZ_TARGETS"

# Enable parallel builds
export MAKEFLAGS+="-j$(nproc)"

echo "[build-apply.sh] Rebuilding curl (incremental)..."
# Incrementally rebuild curl
# Only changed files will be recompiled
pushd /src/curl
make V=1
make install
popd

echo "[build-apply.sh] Rebuilding fuzzers..."
# Rebuild the fuzzer infrastructure
# This relinks the fuzzers with the updated curl library
pushd ${BUILD_ROOT}
make
make check
popd

echo "[build-apply.sh] Recreating seed corpus..."
# Recreate the seed corpus zip file
make zip

echo "[build-apply.sh] Copying outputs..."
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

echo "[build-apply.sh] Incremental build completed successfully!"
