#!/bin/bash
set -e

BUILD_DIR=build
mkdir -p ${BUILD_DIR}
pushd ${BUILD_DIR}

# Only run meson setup on first run
if [ ! -f build.ninja ]; then
    meson setup .. -Dtestdata_tests=true
fi

ninja
meson test -v