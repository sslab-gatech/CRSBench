#!/bin/bash
set -e

# test.sh for jq benchmark
# This script builds jq from scratch and runs its test suite

echo "=== Building jq from scratch ==="

# Ensure modules directory exists and copy oniguruma
# The modules/oniguruma might be a symlink or directory from Docker image
rm -rf modules
mkdir -p modules
cp -r /src/oniguruma modules/

# Generate build files for jq
autoreconf -fi

# Configure with builtin oniguruma (this will build oniguruma automatically)
./configure --with-oniguruma=builtin

# Build jq (this also builds the oniguruma submodule)
make -j$(nproc)

echo "=== Running jq tests ==="

# Run the test suite
# jq uses 'make check' which runs multiple test scripts
make check

echo "=== All tests passed ==="
