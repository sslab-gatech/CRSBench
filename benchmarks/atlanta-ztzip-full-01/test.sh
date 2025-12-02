#!/bin/bash

set -ex

# Clean and create target directory if it doesn't exist
rm -rf target || true
mkdir -p target

# Run Maven tests with parallel execution
mvn clean test \
  -Dtest=ZTFileUtilTest,ZipEntryUtilTest,ZipPreserveTimeStampTest,MainExamplesTest,CharsetTest,ZipUtilDirTest,ZipsTest,FileSourceTest,ZipPreserveTimeStampJava8Test,ZipUtilInPlaceTest,ZipUtilTest,ZipTransformTest \
  -T"$(nproc)"
