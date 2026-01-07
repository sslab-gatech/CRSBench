#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set -e
set -o pipefail

# set parallel value
: "${NPROC_VAL:=$(nproc)}"

warn() {
    echo "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

# Build nginx binary in separate directory to avoid ASAN object file conflicts
NGINX_TEST_DIR="$SRC/nginx_for_test"
mkdir -p $NGINX_TEST_DIR

export CFLAGS="-O0 -g"
export CXXFLAGS="-O1 -stdlib=libc++"
export LIBS="-ldl -lpthread"

if [ ! -f objs/Makefile ]; then
    ./auto/configure \
        --with-cc-opt="${CFLAGS}" \
        --with-ld-opt="${LIBS}"\
        --conf-path=$NGINX_TEST_DIR/conf/nginx.conf \
        --pid-path=$NGINX_TEST_DIR/logs/nginx.pid \
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
        --with-http_stub_status_module \
        --with-http_slice_module \
        --with-stream \
        --with-pcre \
        --with-debug
fi

while grep -q 'fuzz_without_main' src/core/nginx.c 2>/dev/null; do
    sed -i 's/fuzz_without_main(/main(/g' src/core/nginx.c
    # Force recompile nginx.o since source changed
    rm -f objs/src/core/nginx.o
done

make -f objs/Makefile -j$(nproc)

# Copy nginx binary to OUT
cp objs/nginx $OUT/nginx

export TEST_NGINX_BINARY="${OUT}/nginx"

[[ -x ${TEST_NGINX_BINARY} ]] || \
    die "FAILURE: missing binary: ${TEST_NGINX_BINARY}"
[[ -d ${SRC}/.aixcc/tests/nginx-unit-tests ]] || \
    die "FAILURE: missing test directory: ${SRC}/.aixcc/tests/nginx-unit-tests"

# tell the NGINX it needs to handle running as root
[[ ${EUID} -eq 0 ]] && export TEST_NGINX_GLOBALS="user root;"

# run standard set of tests
prove -j${NPROC_VAL} $(find ${SRC}/.aixcc/tests/nginx-unit-tests \
    -type f \
    ! -name "*LICENSE" \
    ! -name "*README" \
    ! -name "*.pm" \
    ! -name "*.sh" \
    ! -name "*.pcap" \
    ! -name "http_resolver.t" \
    ! -name "http_resolver_ipv4.t" \
    ! -name "auth_delay.t" \
    ! -name "proxy_cache_vary.t" \
    ! -name "limit_req_delay.t" \
    ! -name "stream_upstream.t" \
    ! -name "proxy_cache.t" \
    ! -name "stream_access_log.t" \
    ! -name "proxy_cache_revalidate.t" \
    ! -name "limit_rate.t" \
    ! -name "proxy_limit_rate.t" \
    ! -name "stream_limit_rate.t" \
    ! -name "stream_limit_rate2.t" \
    ! -name "stream_udp_limit_rate.t" \
    ! -name "proxy_cache_valid.t" \
    ! -name "proxy_cache_use_stale.t" \
    ! -name "http_variables.t" \
    ! -name "from.t"
) || exit 2

# run problematic tests x3, ensure triple failure

PROBLEM_TESTS=(
    ${SRC}/.aixcc/tests/nginx-unit-tests/http_resolver.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/http_resolver_ipv4.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/auth_delay.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_cache_vary.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/limit_req_delay.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/stream_upstream.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_cache.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/stream_access_log.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_cache_revalidate.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/limit_rate.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_limit_rate.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/stream_limit_rate.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/stream_limit_rate2.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/stream_udp_limit_rate.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_cache_valid.t
    ${SRC}/.aixcc/tests/nginx-unit-tests/proxy_cache_use_stale.t
)

for pt in "${PROBLEM_TESTS[@]}"; do
    prove -j${NPROC_VAL} ${pt} ||
    prove -j${NPROC_VAL} ${pt} ||
    prove -j${NPROC_VAL} ${pt} || exit 2
done