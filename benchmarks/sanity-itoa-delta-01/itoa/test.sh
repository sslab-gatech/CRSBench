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

BLOB=(test1.blob test2.blob test3.blob)

[[ -x ${OUT}/mock_vp ]] || die "FAILURE: missing binary: ${OUT}/mock_vp"

for blob in "${BLOB[@]}"; do
    [[ -f ${SRC}/.aixcc/tests/${blob} ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/${blob}"
    ${OUT}/mock_vp < ${SRC}/.aixcc/tests/${blob} | grep -q "Ok" || \
        { warn "FAILURE: ${blob%.*} failed"; exit 2; }
done