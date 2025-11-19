#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set -e
set -o pipefail

warn() {
    echo "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

$CC $CFLAGS -c $SRC/mock-cp-src/mock_vp.c -o $OUT/mock_vp.o
$CXX $CXXFLAGS $OUT/mock_vp.o -o $OUT/mock_vp

[[ -x ${OUT}/mock_vp ]] || die "FAILURE: missing binary: ${OUT}/mock_vp"
[[ -f ${SRC}/.aixcc/tests/test1.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.blob"
[[ -f ${SRC}/.aixcc/tests/test2.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test2.blob"

${OUT}/mock_vp < ${SRC}/.aixcc/tests/test1.blob | grep -q "apple" || \
    { warn "FAILURE: test1 failed"; exit 2; }

${OUT}/mock_vp < ${SRC}/.aixcc/tests/test2.blob | grep -q "bicycle" || \
    { warn "FAILURE: test2 failed"; exit 2; }