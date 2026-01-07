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

# Incremental build compatible version of ossfuzz.sh
# Based on curl-fuzzer/ossfuzz.sh but with idempotent guards

# Parse the options.
OPTIND=1
CODE_COVERAGE_OPTION=""

while getopts "c" opt
do
    case "$opt" in
        c) CODE_COVERAGE_OPTION="--enable-code-coverage"
           ;;
    esac
done
shift $((OPTIND-1))

export BUILD_ROOT=$SRC/curl_fuzzer
SCRIPTDIR=${BUILD_ROOT}/scripts

. ${SCRIPTDIR}/fuzz_targets

ZLIBDIR=$SRC/zlib
OPENSSLDIR=$SRC/openssl
NGHTTPDIR=$SRC/nghttp2
GDBDIR=$SRC/gdb

# Always use -O0 so the bugs don't get optimized out
export CFLAGS="$CFLAGS -O0"
export CXXFLAGS="$CXXFLAGS -O0"

export MAKEFLAGS+="-j$(nproc)"
export INSTALLDIR=$SRC/curl_install
mkdir -p ${INSTALLDIR}

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile and installing GDB if necessary.
if [[ -n ${GDBMODE:-} ]]
then
  if ! type gdb 2>/dev/null
  then
    # If gdb isn't found, then download and install GDB.
    # This installs to the default configure location.
    ${SCRIPTDIR}/handle_x.sh gdb ${GDBDIR} system || exit 1
  fi
fi

# Download and install zlib (skip if already installed)
if [[ ! -f ${INSTALLDIR}/lib/libz.a ]]; then
    # Download zlib if not present
    if [[ ! -d ${ZLIBDIR} ]]; then
        ${SCRIPTDIR}/download_zlib.sh ${ZLIBDIR}
    fi
    pushd ${ZLIBDIR}
    if [[ ! -f Makefile ]] || ! grep -q '^prefix=' Makefile 2>/dev/null; then
        ./configure --prefix=${INSTALLDIR} --static
    fi
    make -j$(nproc)
    make install
    popd
fi

# Download and install openssl (skip if already installed, and only for non-memory sanitizer)
if [[ ${SANITIZER} != "memory" ]] && [[ ! -f ${INSTALLDIR}/lib/libssl.a ]]; then
    # Download openssl if not present
    if [[ ! -d ${OPENSSLDIR} ]]; then
        ${SCRIPTDIR}/download_openssl.sh ${OPENSSLDIR}
    fi
    if [[ ${ARCHITECTURE} == "i386" ]]; then
        ARCH_PROG="setarch i386"
        EC_FLAG="no-threads"
    else
        ARCH_PROG=""
        EC_FLAG="enable-ec_nistp_64_gcc_128"
    fi
    if [[ ${SANITIZER} == "memory" ]]; then
        ASM_FLAG="no-asm"
    else
        ASM_FLAG=""
    fi
    export OPENSSLFLAGS="-fno-sanitize=alignment"
    pushd ${OPENSSLDIR}
    if [[ ! -f Makefile ]]; then
        ${ARCH_PROG} ./config --prefix=${INSTALLDIR} \
                              --libdir=lib \
                              --debug \
                              enable-fuzz-libfuzzer \
                              --with-fuzzer-lib=/usr/lib/libFuzzingEngine \
                              -DPEDANTIC \
                              -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
                              no-shared \
                              ${ASM_FLAG} \
                              enable-tls1_3 \
                              enable-rc5 \
                              enable-md2 \
                              enable-ssl3 \
                              ${EC_FLAG} \
                              enable-ssl3-method \
                              enable-nextprotoneg \
                              enable-weak-ssl-ciphers \
                              $CFLAGS \
                              ${OPENSSLFLAGS}
    fi
    make -j$(nproc)
    make install_sw
    popd
fi

# Download and install nghttp2 (skip if already installed)
if [[ ! -f ${INSTALLDIR}/lib/libnghttp2.a ]]; then
    # Download nghttp2 if not present
    if [[ ! -d ${NGHTTPDIR} ]]; then
        ${SCRIPTDIR}/download_nghttp2.sh ${NGHTTPDIR}
    fi
    pushd ${NGHTTPDIR}
    if [[ ! -f Makefile ]]; then
        autoreconf -i
        ./configure --prefix=${INSTALLDIR} \
                    --disable-shared \
                    --enable-static \
                    --disable-threads --enable-lib-only
    fi
    make -j$(nproc)
    make install
    popd
fi

# Install curl
pushd $SRC/curl
if [[ -f ${INSTALLDIR}/lib/libssl.a ]]; then
    SSLOPTION=--with-ssl=${INSTALLDIR}
else
    SSLOPTION=--without-ssl
fi
if [[ -f ${INSTALLDIR}/lib/libnghttp2.a ]]; then
    NGHTTPOPTION=--with-nghttp2=${INSTALLDIR}
else
    NGHTTPOPTION=--without-nghttp2
fi

if [[ ! -f configure ]]; then
    autoreconf -fi
fi

if [[ ! -f Makefile ]]; then
    ./configure --prefix=${INSTALLDIR} \
                --disable-shared \
                --enable-debug \
                --enable-maintainer-mode \
                --disable-symbol-hiding \
                --enable-ipv6 \
                --enable-websockets \
                --without-libpsl \
                --with-random=/dev/null \
                ${SSLOPTION} \
                ${NGHTTPOPTION} \
                ${CODE_COVERAGE_OPTION}
fi

make -j$(nproc) V=1
make install

# Make any explicit folders which are post install
UTFUZZDIR=${INSTALLDIR}/utfuzzer
mkdir -p ${UTFUZZDIR}

# Copy header files
cp -v lib/curl_fnmatch.h ${UTFUZZDIR}
cp -v lib/bufq.h ${UTFUZZDIR}
touch ${UTFUZZDIR}/curl_setup.h

popd

# Build the fuzzers
pushd ${BUILD_ROOT}

if [[ ! -f configure ]]; then
    autoreconf -fi
fi

if [[ ! -f Makefile ]]; then
    ./configure ${CODE_COVERAGE_OPTION}
fi

make -j$(nproc)
make zip

# Copy the fuzzers over
for TARGET in $FUZZ_TARGETS; do
    cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
done

# Copy dictionary and options file to $OUT
cp -v ossconfig/*.dict ossconfig/*.options $OUT/

popd
