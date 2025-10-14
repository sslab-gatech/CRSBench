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

[[ -x ${OUT}/fuzz ]] || die "FAILURE: missing binary: ${OUT}/fuzz"
[[ -f ${SRC}/.aixcc/tests/test1.cue ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.cue"

# general testing
cd ${WORK}; make test

# parse some cue files
${OUT}/fuzz ${SRC}/.aixcc/tests/test1.cue 2>&1 | grep -q "Executed" || \
    { warn "FAILURE: test1 failed"; exit 2; }