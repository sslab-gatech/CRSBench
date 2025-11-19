#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.
set -x
set -e
set -o pipefail


HAS_FAILURE=false
FAILURE_STRING=''
ANY_TESTS_RUN=false

warn() {
  echo "$*" >&2
}

die() {
  warn "$*"
  exit 1
}
#report that there were test failures, exit value=1
report_test_failure() {
    echo "${FAILURE_STRING}"
    exit 2
}

all_good() {
    echo "tests all passed!"
    exit 0
}

build_test() {
  local test_output
  test_output=$(${CC} ${CFLAGS} -D___TEST___ -I${SRC}/cp-user-timeouts-and-crashes-src -o ${OUT}/test ${SRC}/.aixcc/tests/test.c ${LDFLAGS} ${LIBS} 2>&1) || {
    FAILURE_STRING="Build failed with error: ${test_output}"
    return 1
  }
  return 0
}

run_test() {
  local test_output
  test_output=$(${OUT}/test 2>&1) || {
    FAILURE_STRING="Test failed with error: ${test_output}"
    return 1
  }
  return 0
}


build_test || die "${FAILURE_STRING}"

run_test || report_test_failure

all_good
