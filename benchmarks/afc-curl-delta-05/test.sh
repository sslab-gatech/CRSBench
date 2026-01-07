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

set +e
echo "Running tests…"
# Retry logic for flaky tests, but still let the exit code reflect actual failures
for ((i = 0; i < 3; i++)); do
    if make -C "${CURLSRCDIR}" -k test-full -j"$(nproc)"; then
        break
    else
        if [ $i -eq 2 ]; then
            echo "The tests are probably actually failing. Bailing out"
            exit 1
        else
            echo "Failed, but it might be spurious. Beginning attempt $((i + 2)) of 3"
        fi
    fi
done
echo "Running tests… DONE"

exit 0
