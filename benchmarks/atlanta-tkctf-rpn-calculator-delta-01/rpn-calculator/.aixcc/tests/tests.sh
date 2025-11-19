#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set -e
set -o pipefail

STDOUT_FILE=/tmp/stdout.txt

warn() {
    echo "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

[[ -f ${SRC}/.aixcc/tests/test1.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.blob"
[[ -f ${SRC}/.aixcc/tests/test2.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test2.blob"
[[ -f ${SRC}/.aixcc/tests/test3.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test3.blob"
[[ -f ${SRC}/.aixcc/tests/test4.blob ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test4.blob"

[[ -f ${SRC}/.aixcc/tests/test1.stdout ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test1.stdout"
[[ -f ${SRC}/.aixcc/tests/test2.stdout ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test2.stdout"
[[ -f ${SRC}/.aixcc/tests/test3.stdout ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test3.stdout"
[[ -f ${SRC}/.aixcc/tests/test4.stdout ]] || die "FAILURE: missing test file: ${SRC}/.aixcc/tests/test4.stdout"

${OUT}/filein_harness ${SRC}/.aixcc/tests/test1.blob 1>${STDOUT_FILE} 2>/dev/null
diff ${STDOUT_FILE} ${SRC}/.aixcc/tests/test1.stdout || { warn "FAILURE: test1 failed"; exit 2; }

${OUT}/filein_harness ${SRC}/.aixcc/tests/test2.blob 1>${STDOUT_FILE} 2>/dev/null
diff ${STDOUT_FILE} ${SRC}/.aixcc/tests/test2.stdout || { warn "FAILURE: test2 failed"; exit 2; }

${OUT}/filein_harness ${SRC}/.aixcc/tests/test3.blob 1>${STDOUT_FILE} 2>/dev/null
diff ${STDOUT_FILE} ${SRC}/.aixcc/tests/test3.stdout || { warn "FAILURE: test3 failed"; exit 2; }

${OUT}/filein_harness ${SRC}/.aixcc/tests/test4.blob 1>${STDOUT_FILE} 2>/dev/null
diff ${STDOUT_FILE} ${SRC}/.aixcc/tests/test4.stdout || { warn "FAILURE: test4 failed"; exit 2; }

echo "tests all passed!"

exit 0
