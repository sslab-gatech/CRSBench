#!/bin/bash
set -ex

export BUILD_ROOT=/src/curl_fuzzer

SCRIPTDIR=/src/curl_fuzzer/scripts
OPENSSLDIR=/src/openssl
INSTALLDIR=/src/curl_install
ZLIBDIR=/src/zlib
NGHTTPDIR=/src/nghttp2
CURLSRCDIR=/src/curl

# Install zlib
echo "Installing zlib..."
${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1
echo "Installing zlib... DONE"

# Install openssl
echo "Installing openssl..."
## Download
${SCRIPTDIR}/download_openssl.sh ${OPENSSLDIR}
ls ${OPENSSLDIR}
## Compile and install openssl
pushd ${OPENSSLDIR}
# For i386, set a specific crosscompile mode
if [[ ${ARCHITECTURE} == "i386" ]]
then
    ARCH_PROG="setarch i386"

    # Disabled as per https://github.com/google/oss-fuzz/blob/master/projects/openssl/build.sh
    EC_FLAG="no-threads"
else
    ARCH_PROG=""
    EC_FLAG="enable-ec_nistp_64_gcc_128"
fi
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
                      $CFLAGS \

make
make install_sw
echo "Installing openssl... DONE"
popd

# Install nghttp2
echo "Install nghttp2..."
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1
echo "Install nghttp2... DONE"

# Build curl
echo "Building curl..."
if [[ ! -d ${INSTALLDIR} ]]
then
  # Make an install target for curl.
  mkdir ${INSTALLDIR}
fi

if [[ -f ${INSTALLDIR}/lib/libssl.a ]]
then
  SSLOPTION=--with-ssl=${INSTALLDIR}
else
  SSLOPTION=--without-ssl
fi

if [[ -f ${INSTALLDIR}/lib/libnghttp2.a ]]
then
  NGHTTPOPTION=--with-nghttp2=${INSTALLDIR}
else
  NGHTTPOPTION=--without-nghttp2
fi

pushd ${CURLSRCDIR}

# Build the library.
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

make V=1
make install
echo "Building curl... DONE"

# Run functional tests
## Install dependencies
pip install impacket
## Run
echo "Running tests..."
make test-full
echo "Running tests... DONE"

exit 0
