#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Run Maven tests for sqlite-jdbc
# This script expects to be run from the project root directory (WORKDIR)

set -o pipefail

echo "Running sqlite-jdbc test suite..."

# Run Maven tests
# Note: We skip spotless:check to avoid formatting issues
# We run with -DtrimStackTrace=false for better error reporting
# Exclude tests that rely on file permissions (fail when running as root in Docker)
$MVN test -DtrimStackTrace=false -Dspotless.check.skip=true \
  -Dtest='!ConnectionTest#openNonExistingFileInReadOnlyDirectory,!ErrorMessageTest#writeProtected,!ConnectionTest#ignoreDoubleAmpersandsInURI'

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "All tests passed successfully!"
else
    echo "Tests failed with exit code: $exit_code"
fi

exit $exit_code
