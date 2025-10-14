#!/bin/bash
set -ex

# Clear some variables set by other scripts
unset CC
unset CXX
unset CFLAGS
unset CXXFLAGS
unset RUSTFLAGS

# Turn off IPv6 tests
export IPV6=0

cd test
output=$(make test 2>&1) || true;
echo "$output" > "make_test.log"
if [[ $output == *"SUCCESS. Total tests:"* ]]; then
    echo "SUCCESS tests complete."
    exit 0
fi

echo "FAILED to run tests."
exit 1

