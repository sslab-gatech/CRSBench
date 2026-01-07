#!/bin/bash
set -ex

export BUILD_ROOT=$SRC/curl_fuzzer

SCRIPTDIR=$SRC/curl_fuzzer/scripts
OPENSSLDIR=$SRC/openssl
INSTALLDIR=$SRC/curl_install
ZLIBDIR=$SRC/zlib
NGHTTPDIR=$SRC/nghttp2
CURLSRCDIR=$SRC/curl

# Install zlib (uses handle_x.sh which has incremental build guard)
echo "Installing zlib..."
${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1
echo "Installing zlib... DONE"

# Install openssl (skip if already installed)
echo "Installing openssl..."
if [[ ! -f ${INSTALLDIR}/lib/libssl.a ]]; then
    ## Download if not present
    if [[ ! -d ${OPENSSLDIR} ]]; then
        ${SCRIPTDIR}/download_openssl.sh ${OPENSSLDIR}
    fi
    ls ${OPENSSLDIR}
    ## Compile and install openssl
    pushd ${OPENSSLDIR}
    # For i386, set a specific crosscompile mode
    if [[ ${ARCHITECTURE:-x86_64} == "i386" ]]; then
        ARCH_PROG="setarch i386"
        EC_FLAG="no-threads"
    else
        ARCH_PROG=""
        EC_FLAG="enable-ec_nistp_64_gcc_128"
    fi

    # Only configure if Makefile doesn't exist
    if [[ ! -f Makefile ]]; then
        ${ARCH_PROG} ./config --prefix=${INSTALLDIR} \
                              --libdir=lib \
                              --debug \
                              no-shared \
                              enable-tls1_3 \
                              enable-rc5 \
                              enable-md2 \
                              enable-ssl3 \
                              ${EC_FLAG} \
                              enable-ssl3-method \
                              enable-nextprotoneg \
                              enable-weak-ssl-ciphers \
                              ${CFLAGS:-}
    fi

    make -j$(nproc)
    make install_sw
    popd
fi
echo "Installing openssl... DONE"

# Install nghttp2 (uses handle_x.sh which has incremental build guard)
echo "Install nghttp2..."
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1
echo "Install nghttp2... DONE"

# Build curl
echo "Building curl..."
mkdir -p ${INSTALLDIR}

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

pushd ${CURLSRCDIR}

# Only run buildconf/configure if Makefile doesn't exist (incremental build)
if [[ ! -f Makefile ]]; then
    ./buildconf
    ./configure --prefix=${INSTALLDIR} \
                --disable-shared \
                --disable-debug \
                --enable-maintainer-mode \
                --disable-symbol-hiding \
                --enable-ipv6 \
                --enable-websockets \
                --without-libpsl \
                --with-random=/dev/null \
                ${SSLOPTION} \
                ${NGHTTPOPTION}
fi

make -j$(nproc) V=1
make install
echo "Building curl... DONE"

# Run functional tests
## Install dependencies only if not already installed
if ! python3 -c "import impacket" 2>/dev/null; then
    pip install impacket
fi

## Run
echo "Running tests..."
# Use -k to continue through failures, but DO NOT use || true
make -k test-full -j$(nproc)
echo "Running tests... DONE"

exit 0
