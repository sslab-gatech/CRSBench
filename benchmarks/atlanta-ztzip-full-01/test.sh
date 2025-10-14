#!/bin/bash

set -e

# Clean and create target directory if it doesn't exist
rm -rf target || true
mkdir -p target

# Run Maven tests with parallel execution
mvn clean test -T$(nproc)
