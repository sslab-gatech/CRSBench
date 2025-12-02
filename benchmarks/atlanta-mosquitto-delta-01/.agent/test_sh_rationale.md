# test.sh Rationale for atlanta-mosquitto-delta-01

## Overview
This test.sh script runs the CUnit unit tests for the Mosquitto project, which is an MQTT broker implementation.

## Build Environment Assumptions
- **Clean state**: test.sh runs in a Docker container with NO pre-built artifacts
- **No /out or /work directories**: All fuzzer binaries and build cache are deleted before execution
- **Fresh source code**: The source is mounted in a completely unbuilt state

## Test Framework
- **Framework**: CUnit (C unit testing framework)
- **Test Location**: `test/unit/libcommon/`
- **Test Type**: Unit tests for the libcommon module

## Build Strategy
The script builds from scratch in the correct dependency order:

1. **cJSON dependency** (always build first)
   - Located at `/src/cJSON`
   - Built with CMake and installed system-wide
   - Required by Mosquitto's libcommon module

2. **libcommon** (Mosquitto common library)
   - Core utilities used across the project
   - Must be built before lib and src

3. **lib** (Mosquitto client library)
   - MQTT client library implementation
   - Depends on libcommon

4. **src** (Mosquitto broker)
   - The broker implementation
   - Depends on both libcommon and lib
   - Built with `WITH_DOCS=no WITH_FUZZING=no WITH_EDITLINE=no` flags

## Test Execution
After building, the script runs:
- **libcommon unit tests**: `make -C test/unit/libcommon test`
  - Tests for UTF-8 handling (`utf8.c`)
  - Tests for topic validation (`topic_test.c`)
  - Tests for string utilities (`strings_test.c`)
  - Tests for MQTT property handling (`property_add.c`, `property_value.c`)
  - Tests for trimming functions (`trim_test.c`)

- **Optional tests** (if directories exist):
  - broker unit tests
  - lib unit tests

## Key Implementation Details
1. **Always rebuild cJSON**: No conditional checks - always build from scratch
2. **Parallel builds**: Uses `-j$(nproc)` for faster compilation
3. **Error handling**: Script uses `set -e` to fail fast on any error
4. **Output suppression**: Build output is visible to help debug issues

## Test Coverage
The unit tests cover critical functionality:
- UTF-8 validation (important for CVE prevention)
- Topic parsing and validation
- MQTT v5 property handling
- String manipulation utilities

## Rationale for Test Selection
- **libcommon tests are mandatory**: These test core functionality used throughout the project
- **broker/lib tests are optional**: Marked with `|| true` as they may not always be present or may depend on additional configuration
