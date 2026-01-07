#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
# build.sh builds fuzzers only. nginx binary is built by test.sh separately.

# Setup fuzzer sources (only if not already done)
[ ! -d src/fuzz ] && cp -r $SRC/fuzz src/

# Apply patch and copy make_fuzzers (patch is idempotent with || true)
if [ ! -f auto/make_fuzzers ]; then
    cp $SRC/make_fuzzers auto/make_fuzzers
    patch -p1 < $SRC/add_fuzzers.diff || true
fi

: "${CP_HARNESS_LDFLAGS:="-Wl,--wrap=writev \
    -Wl,--wrap=open \
    -Wl,--wrap=getsockopt \
    -Wl,--wrap=select \
    -Wl,--wrap=recv \
    -Wl,--wrap=read \
    -Wl,--wrap=send \
    -Wl,--wrap=epoll_create \
    -Wl,--wrap=epoll_create1 \
    -Wl,--wrap=epoll_wait \
    -Wl,--wrap=epoll_ctl \
    -Wl,--wrap=close \
    -Wl,--wrap=ioctl \
    -Wl,--wrap=listen \
    -Wl,--wrap=accept \
    -Wl,--wrap=accept4 \
    -Wl,--wrap=setsockopt \
    -Wl,--wrap=bind \
    -Wl,--wrap=shutdown \
    -Wl,--wrap=connect \
    -Wl,--wrap=getpwnam \
    -Wl,--wrap=getgrnam \
    -Wl,--wrap=chmod \
    -Wl,--wrap=chown"}"
: "${CP_HARNESS_LIBS:="-lpthread"}"

export CFLAGS="${CFLAGS} -DNGX_DEBUG_PALLOC=1"

# Configure for fuzzers if Makefile doesn't exist
if [ ! -f objs/Makefile ]; then
    ./auto/configure \
        --with-ld-opt="${CP_HARNESS_LDFLAGS} ${CP_HARNESS_LIBS}"\
        --with-cc-opt="${CFLAGS}" \
        --with-mail \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_auth_request_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_degradation_module \
        --with-http_stub_status_module
fi

# Build fuzzers only
make -f objs/Makefile -j$(nproc) fuzzers

cp objs/*_harness $OUT/

mkdir -p $OUT/html
mkdir -p $OUT/logs
mkdir -p $OUT/videos
mkdir -p $OUT/dav
mkdir -p $OUT/dav/copy_this_dir
echo "hello" > $OUT/dav/copy_this_dir/copy_this_file.txt

cp $SRC/nginx/docs/html/index.html $OUT/html/index.html
cp $SRC/nginx/docs/html/sub.html $OUT/html/sub.html
dd if=/dev/urandom of="$OUT/videos/sample.flv" bs=1M count=1 status=none

rsync -a --delete $SRC/nginx/ $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi
