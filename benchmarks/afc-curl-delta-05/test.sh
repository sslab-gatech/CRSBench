#!/usr/bin/env bash
set -euxo pipefail

export CFLAGS="${CFLAGS:-} -fsanitize=address -fno-omit-frame-pointer"
export CXXFLAGS="${CXXFLAGS:-} -fsanitize=address -fno-omit-frame-pointer -stdlib=libc++"
export LDFLAGS="${LDFLAGS:-} -fsanitize=address"

export BUILD_ROOT=/src/curl_fuzzer/

INSTALLDIR=/src/curl_install
CURLSRCDIR=/src/curl

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential autoconf automake libtool pkg-config \
  zlib1g-dev libssl-dev libnghttp2-dev clang lld


echo "Building curl…"
mkdir -p "${INSTALLDIR}"
pushd "${CURLSRCDIR}"


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

make -C tests clean
make -j"$(nproc)" V=1
make install

popd
echo "Building curl… DONE"

pip install --break-system-packages impacket

set +e
echo "Running tests…"
for ((i = 0; i < 3; i++)); do
    if make -C "${CURLSRCDIR}" test-full -j"$(nproc)"; then
        break
    else
        if [ $i -eq 3 ]; then
            echo "The tests are probably actually failing. Bailing out"
            exit 1
        else
            echo "Failed, but it might be spurious. Beginning attempt ($((i + 1)) of 3"
        fi
    fi
done
echo "Running tests… DONE"

exit 0
