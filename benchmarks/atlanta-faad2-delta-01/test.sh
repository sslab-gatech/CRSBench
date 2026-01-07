#!/bin/bash -eu

export USE_BAZEL_VERSION=7.4.0

# Disable ccache for Bazel builds - ccache is incompatible with Bazel's caching
export PATH=$(echo "$PATH" | sed 's|/ccache/bin:||g; s|:/ccache/bin||g')
unset CC CXX
export CC=clang
export CXX=clang++

# Build the CLI binary
echo "Building FAAD2 CLI with Bazel..."
bazel build //:faad_cli --verbose_failures

# Test the CLI binary by decoding sample AAC file
echo "Testing faad_cli binary with sample.aac..."
./bazel-bin/faad_cli -o /tmp/sample.wav $SRC/sample.aac

echo "Test completed successfully"
exit 0
