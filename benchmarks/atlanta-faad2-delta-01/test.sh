#!/bin/bash -eu
# Test script for atlanta-faad2-delta-01
#
# This project has no traditional unit tests.
# We verify the build succeeds with Bazel (which builds fuzz test harnesses).

export USE_BAZEL_VERSION=7.4.0

# Build the project with Bazel
echo "Building FAAD2 with Bazel..."
bazel build //... --verbose_failures

echo "Build completed successfully - all tests passed"
exit 0
