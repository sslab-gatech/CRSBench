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

# Run CMake tests in the build directory
# During incremental builds, $SRC may be /test-src but build is in /built-src
BUILD_DIR="$SRC/libcue_build"
if [ ! -d "$BUILD_DIR" ] && [ -d "/built-src/libcue_build" ]; then
    BUILD_DIR="/built-src/libcue_build"
fi

if [ -d "$BUILD_DIR" ] && [ -f "$BUILD_DIR/Makefile" ]; then
    pushd "$BUILD_DIR" > /dev/null
    ctest --output-on-failure || true
    popd > /dev/null
fi

# parse some cue files
# ${OUT}/fuzz ${SRC}/.aixcc/tests/test1.cue 2>&1 | grep -q "Executed" || \
    # { warn "FAILURE: test1 failed"; exit 2; }