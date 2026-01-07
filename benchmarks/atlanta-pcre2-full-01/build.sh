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

# Common configure options for fuzzing
FUZZ_CONFIGURE_OPTS="--enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000 --enable-jit"

# Build project (default link-size=2)
# Only run autogen and configure on first run
if [ ! -f configure ]; then
    ./autogen.sh
fi

BUILD_DIR=build_fuzzer
mkdir -p $BUILD_DIR
pushd $BUILD_DIR

if [ ! -f "Makefile" ]; then
    ../configure $FUZZ_CONFIGURE_OPTS
fi

make -j$(nproc) all

# Build default fuzzer
$CXX $CXXFLAGS -o $OUT/pcre2_fuzzer \
    $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

popd

# Build different link sizes - only on first build (skip on incremental builds)
# These require full rebuilds which defeats incremental build purpose
for i in $(seq 3 4); do
    BUILD_DIR=build_fuzzer_${i}
    mkdir -p $BUILD_DIR
    pushd $BUILD_DIR
    if [ ! -f "Makefile" ]; then
        ../configure $FUZZ_CONFIGURE_OPTS --with-link-size=${i}
    fi
    
    make -j$(nproc) all

    # Build fuzzer for this link size
    $CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_${i}l \
        $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a
    popd
done

# Set up dictionary and options
cp "testdata/fuzzing/pcre2_fuzzer.dict" "${OUT}/pcre2_fuzzer.dict"
for linksize in "" "_3l" "_4l"; do
    cp "testdata/fuzzing/pcre2_fuzzer.options" "${OUT}/pcre2_fuzzer${linksize}.options"
done
