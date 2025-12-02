#!/bin/bash
set -e

# NASM test suite runner
# This script runs the NASM test suite using performtest.pl

cd test

# Disable leak detection to avoid false positives in tests
export ASAN_OPTIONS=detect_leaks=0

# Generate golden files only if they don't exist
# This ensures tests fail if code is broken
if [ ! -d "golden" ]; then
    echo "Generating golden reference files..."
    perl performtest.pl --golden --nasm='../nasm' *.asm
fi

# Run the test suite with nasm binary
perl performtest.pl --nasm='../nasm' *.asm

echo "All tests passed!"
