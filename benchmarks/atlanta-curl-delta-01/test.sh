#!/usr/bin/env bash
set -euxo pipefail

export CFLAGS="${CFLAGS:-} -fsanitize=address -fno-omit-frame-pointer"
export CXXFLAGS="${CXXFLAGS:-} -fsanitize=address -fno-omit-frame-pointer -stdlib=libc++"
export LDFLAGS="${LDFLAGS:-} -fsanitize=address"

export BUILD_ROOT=$SRC/curl_fuzzer/

INSTALLDIR=$SRC/curl_install
CURLSRCDIR=$SRC/curl

# Install dependencies only if not already installed
if ! command -v autoconf &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool pkg-config \
      zlib1g-dev libssl-dev libnghttp2-dev clang lld
fi

echo "Building curl…"
mkdir -p "${INSTALLDIR}"
pushd "${CURLSRCDIR}"

# Only run buildconf/configure if Makefile doesn't exist (incremental build)
if [ ! -f Makefile ]; then
    ./buildconf
    ./configure --prefix="${INSTALLDIR}" \
                --disable-shared \
                --enable-debug \
                --enable-maintainer-mode \
                --disable-symbol-hiding \
                --enable-ipv6 \
                --enable-websockets \
                --without-libpsl \
                --with-random=/dev/null \
                --with-ssl \
                --with-nghttp2
fi

# DO NOT run "make -C tests clean" - it destroys incremental build
make -j"$(nproc)" V=1
make install

popd
echo "Building curl… DONE"

# Install pip package only if not already installed
if ! python3 -c "import impacket" 2>/dev/null; then
    pip install --break-system-packages impacket
fi

echo "Running tests…"
# Use -k to continue through failures, but DO NOT use || true
make -C "${CURLSRCDIR}" -k test-full -j"$(nproc)"
echo "Running tests… DONE"

exit 0
