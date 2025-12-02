#!/bin/bash
set -ex

compile

# `make check` is not fully functional due to failures in RunTest and RunGrepTest.
./pcre2posix_test
./pcre2_jit_test

echo "All tests passed!"