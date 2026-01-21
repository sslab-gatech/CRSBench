#!/bin/bash
set -ex
set -o pipefail

# Simple test script for sanity-missing-vulnerabilities
# Run the fuzzer with a short timeout to verify it works
cd $OUT

# Run fuzzer for a short time to verify it starts correctly
timeout 10 ./fuzz -runs=100

echo "Test completed successfully"
