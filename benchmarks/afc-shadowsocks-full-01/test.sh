#!/bin/bash

# shadowsocks has submodules, untar them into the correct place from $SRC/aixcc-submodules
tar -zxf ../aixcc-submodules/submodules.tar.gz

apt-get install --no-install-recommends -y pkg-config gettext build-essential \
    autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev dnsutils \
    automake libmbedtls-dev libsodium-dev
./autogen.sh
./configure
make V=1

# Run Tests
tests/test.sh

