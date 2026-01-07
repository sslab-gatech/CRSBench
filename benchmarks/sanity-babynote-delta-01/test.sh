#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set -ex
set -o pipefail

warn() {
    echo "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

[[ -x ${OUT}/mock_vp ]] || die "FAILURE: missing binary: ${OUT}/mock_vp"
[[ -f ${SRC}/.aixcc/tests/test1.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.blob"
[[ -f ${SRC}/.aixcc/tests/test2.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test2.blob"
[[ -f ${SRC}/.aixcc/tests/test3.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test3.blob"

${OUT}/mock_vp < ${SRC}/.aixcc/tests/test1.blob | grep -q "aaaaa" || \
    { warn "FAILURE: test1 failed"; exit 2; }

${OUT}/mock_vp < ${SRC}/.aixcc/tests/test2.blob | grep -q "aaaaa" || \
    { warn "FAILURE: test2 failed"; exit 2; }

${OUT}/mock_vp < ${SRC}/.aixcc/tests/test3.blob | grep -q "bbbbb" || \
    { warn "FAILURE: test3 failed"; exit 2; }