#!/bin/bash
set -e

BUILD_DIR=build_test
mkdir -p ${BUILD_DIR}
pushd ${BUILD_DIR}
cmake .. -DBUILD_TESTING=1
make all -j
make test
