#!/bin/bash
set -ex

# shadowsocks has submodules, untar them into the correct place from $SRC/aixcc-submodules
tar -zxf ../aixcc-submodules/submodules.tar.gz

apt-get install --no-install-recommends -y pkg-config gettext build-essential \
    autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev dnsutils \
    automake libmbedtls-dev libsodium-dev

if [[ ! -f configure ]]; then
    autoreconf -fi
fi

if [[ ! -f Makefile ]]; then
    ./configure
fi
make V=1

# Run Tests
tests/test.sh