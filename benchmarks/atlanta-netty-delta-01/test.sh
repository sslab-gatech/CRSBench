#!/bin/bash -eu
# Copyright 2024 CRSBench
#
# Test script for atlanta-netty-delta-01
# This script runs unit tests for the Netty project
#
# Environment:
# - test.sh is located at /src/test.sh in the container
# - test.sh is executed from WORKDIR (/src/netty)
# - Project source code is mounted at WORKDIR

set -e

# Maven is configured in the environment
MVN="${MVN:-/src/maven-3.6.3/apache-maven-3.6.3/bin/mvn}"

echo "[test.sh] Running Netty unit tests from $(pwd)"

# First, install dependencies without running tests
echo "[test.sh] Building dependencies..."
$MVN install \
  -Dcheckstyle.skip=true \
  -DskipTests \
  -pl common \
  -am

# Now run a focused set of fast tests from buffer module
echo "[test.sh] Running buffer module tests..."
$MVN test \
  -Dcheckstyle.skip=true \
  -pl buffer \
  -Dtest=ByteBufUtilTest,EmptyByteBufTest,IntPriorityQueueTest

echo "[test.sh] Tests completed successfully"
