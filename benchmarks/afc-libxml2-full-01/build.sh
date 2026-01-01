#!/bin/bash -eu
#
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

# Rewritten from fuzz/oss-fuzz-build.sh for incremental build support

# Add extra UBSan checks
if [ "$SANITIZER" = undefined ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="$CFLAGS $extra_cflags"
    export CXXFLAGS="$CXXFLAGS $extra_cflags"
fi

# Don't enable zlib and liblzma with MSan
if [ "$SANITIZER" = memory ]; then
    CONFIG=''
else
    CONFIG='--with-zlib --with-lzma'
fi

# Workaround for a LeakSanitizer crashes
if [ "$ARCHITECTURE" = "aarch64" ]; then
    export ASAN_OPTIONS=detect_leaks=0
fi

export V=1


# Conditional configure for incremental builds
if [ ! -f Makefile ]; then
    ./autogen.sh \
        --disable-shared \
        --without-debug \
        --without-http \
        --without-python \
        $CONFIG
fi

make -j$(nproc)

cd fuzz
make clean-corpus
make fuzz.o

for fuzzer in \
    api html lint reader regexp schema uri valid xinclude xml xpath
do
    make $fuzzer.o
    # Link with $CXX
    $CXX $CXXFLAGS \
        $fuzzer.o fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

    if [ $fuzzer != api ]; then
        [ -e seed/$fuzzer ] || make seed/$fuzzer.stamp
        zip -j $OUT/${fuzzer}_seed_corpus.zip seed/$fuzzer/*
    fi
done

cp *.dict *.options $OUT/
