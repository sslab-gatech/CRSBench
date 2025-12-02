#!/bin/bash -eu
# Copyright 2025 CRSBench
#
# Test script for tmux (atlanta-tmux-delta-01)
# Executes regression tests from the regress/ directory
#
# This script:
# 1. Builds tmux from source (configure + make)
# 2. Runs regression tests from regress/ directory
# 3. Returns 0 on success, non-zero on failure

set -o pipefail

# Script location: /src/test.sh
# Execution directory: /src/tmux (WORKDIR)
# Source code: /src/tmux

echo "[test.sh] Starting tmux regression test suite"
echo "[test.sh] Working directory: $(pwd)"

# Ensure we're in the project root
cd /src/tmux || { echo "[test.sh] ERROR: Cannot cd to /src/tmux"; exit 1; }

# Clean any previous build artifacts
echo "[test.sh] Cleaning previous build artifacts..."
if [ -f Makefile ]; then
    make clean 2>/dev/null || true
fi
rm -f config.log config.status Makefile 2>/dev/null || true

# Step 1: Generate configure script
echo "[test.sh] Running autogen.sh..."
if [ ! -f ./autogen.sh ]; then
    echo "[test.sh] ERROR: autogen.sh not found"
    exit 1
fi
./autogen.sh || { echo "[test.sh] ERROR: autogen.sh failed"; exit 1; }

# Step 2: Configure the build
echo "[test.sh] Running configure..."
if [ ! -f ./configure ]; then
    echo "[test.sh] ERROR: configure script not generated"
    exit 1
fi

# Configure without fuzzing for normal testing
./configure --enable-static \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a " || \
    { echo "[test.sh] ERROR: configure failed"; exit 1; }

# Step 3: Build tmux
echo "[test.sh] Building tmux..."
make -j"$(nproc)" || { echo "[test.sh] ERROR: make failed"; exit 1; }

# Verify tmux binary exists
if [ ! -f ./tmux ]; then
    echo "[test.sh] ERROR: tmux binary not built"
    exit 1
fi

echo "[test.sh] Build successful, tmux binary created"
./tmux -V || true

# Step 4: Run regression tests
echo "[test.sh] Running regression tests..."

if [ ! -d regress ]; then
    echo "[test.sh] ERROR: regress/ directory not found"
    exit 1
fi

cd regress || { echo "[test.sh] ERROR: Cannot cd to regress/"; exit 1; }

# Set TEST_TMUX to use the newly built binary
export TEST_TMUX="/src/tmux/tmux"
export PATH="/src/tmux:$PATH"

# List of stable tests (20 tests that consistently pass)
STABLE_TESTS="
am-terminal.sh
command-order.sh
conf-syntax.sh
control-client-sanity.sh
control-client-size.sh
cursor-test1.sh
cursor-test2.sh
cursor-test3.sh
cursor-test4.sh
format-strings.sh
has-session-return.sh
if-shell-TERM.sh
if-shell-error.sh
if-shell-nested.sh
kill-session-process-exit.sh
new-session-base-index.sh
new-session-command.sh
new-session-no-client.sh
new-session-size.sh
new-window-command.sh
"

# Run each stable test
PASSED=0
FAILED=0
TOTAL=0

for test in $STABLE_TESTS; do
    if [ ! -f "$test" ]; then
        echo "[test.sh] WARNING: Test file $test not found, skipping"
        continue
    fi

    TOTAL=$((TOTAL + 1))
    echo -n "[test.sh] Running $test... "

    if timeout 10 sh "$test" >/dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
done

echo "[test.sh] =========================================="
echo "[test.sh] Test Results:"
echo "[test.sh]   Total:  $TOTAL"
echo "[test.sh]   Passed: $PASSED"
echo "[test.sh]   Failed: $FAILED"
echo "[test.sh] =========================================="

# Exit with success if all tests passed
if [ $FAILED -eq 0 ] && [ $PASSED -gt 0 ]; then
    echo "[test.sh] ✓ All regression tests passed"
    exit 0
else
    echo "[test.sh] ✗ Some regression tests failed"
    exit 1
fi
