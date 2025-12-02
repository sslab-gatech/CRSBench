#!/bin/bash -eu
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# test.sh for Keycloak - Runs unit tests for core modules

set -e
set -o pipefail

# Environment setup
export MAVEN_OPTS="-Xmx2048m -XX:MaxMetaspaceSize=512m"

# Build and test specific modules without full distribution build
# Focus on modules with standalone unit tests

echo "========================================="
echo "Building and testing common module..."
echo "========================================="
$MVN clean test -pl common -am -B

echo "========================================="
echo "Building and testing core module..."
echo "========================================="
$MVN clean test -pl core -am -B

echo "========================================="
echo "Building and testing saml-core module..."
echo "========================================="
$MVN clean test -pl saml-core -am -B

echo "========================================="
echo "All tests passed successfully!"
echo "========================================="
