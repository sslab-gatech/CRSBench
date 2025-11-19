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

[[ -x ${OUT}/ossfuzz-1 ]] || die "FAILURE: missing binary: ${OUT}/ossfuzz-1"
[[ -f ${SRC}/.aixcc/tests/test1.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.blob"
[[ -f ${SRC}/.aixcc/tests/test2.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test2.blob"
[[ -f ${SRC}/.aixcc/tests/test3.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test3.blob"
[[ -f ${SRC}/.aixcc/tests/test4.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test4.blob"
[[ -f ${SRC}/.aixcc/tests/test5.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test5.blob"

${OUT}/ossfuzz-1 ${SRC}/.aixcc/tests/test1.blob | grep -q "buf1: AAAAAAAAAAAAAAA" || \
    { warn "FAILURE: test1 failed"; exit 2; }

${OUT}/ossfuzz-1 ${SRC}/.aixcc/tests/test2.blob | grep -q "buf2: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" || \
    { warn "FAILURE: test2 failed"; exit 2; }

${OUT}/ossfuzz-1 ${SRC}/.aixcc/tests/test3.blob | grep -q "buf3: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" || \
    { warn "FAILURE: test3 failed"; exit 2; }

${OUT}/ossfuzz-1 ${SRC}/.aixcc/tests/test4.blob | grep -q "buf4: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" || \
    { warn "FAILURE: test4 failed"; exit 2; }

${OUT}/ossfuzz-1 ${SRC}/.aixcc/tests/test5.blob | grep -q "buf5: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" || \
    { warn "FAILURE: test5 failed"; exit 2; }