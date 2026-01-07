#!/bin/bash
set -e

export PIN_ROOT=/opt/pin
export BINARY_RTS=/opt/binary-rts
export PINTOOLS_RTS=$BINARY_RTS/pintools-rts
export PIN_LISTENER_DIR=$PINTOOLS_RTS/pin_listener
RTS_ON=${RTS_ON:-0}
SNAPSHOT_RTS=$(test -d $PIN_ROOT && echo 1 || echo 0)
echo "SNAPSHOT_RTS $SNAPSHOT_RTS RTS_ON $RTS_ON"

PROJECT_CFLAGS="-g -O0 -D_NO_STRING_INLINES -DFORTIFY_SOURCE=0 -fPIC"
PROJECT_LDFLAGS=""

if [[ -n "${CFLAGS}" ]]; then
    PROJECT_CFLAGS="${PROJECT_CFLAGS} ${CFLAGS}"
fi

if [[ -n "${LDFLAGS}" ]]; then
    PROJECT_LDFLAGS="${PROJECT_LDFLAGS} ${LDFLAGS}"
fi

BUILD_DIR=build_test
mkdir -p ${BUILD_DIR}
pushd ${BUILD_DIR}

if [[ ! -f "CMakeCache.txt" ]]; then
    if [[ $SNAPSHOT_RTS -eq 1 ]]; then
        # Append -fno-inline to prevent inlining, needed for Pin function tracing
        PROJECT_CFLAGS="${PROJECT_CFLAGS} -fno-inline"
        cmake -G"Unix Makefiles" \
            -DCMAKE_C_COMPILER="${CC:-clang}" \
            -DCMAKE_C_FLAGS_RELEASE="${PROJECT_CFLAGS}" \
            -DCMAKE_EXE_LINKER_FLAGS_INIT="${PROJECT_LDFLAGS}" \
            -DREQUIRE_SIMD=0 \
            -DWITH_SIMD=0 \
            -DENABLE_PIN_LISTENER=ON \
            -DCMAKE_BUILD_TYPE=Debug \
            ..
    else
        cmake -G"Unix Makefiles" \
            -DCMAKE_C_COMPILER="${CC:-clang}" \
            -DCMAKE_C_FLAGS_RELEASE="${PROJECT_CFLAGS}" \
            -DCMAKE_EXE_LINKER_FLAGS_INIT="${PROJECT_LDFLAGS}" \
            -DREQUIRE_SIMD=0 \
            -DWITH_SIMD=0 \
            ..
    fi
fi

make -j$(nproc)

COVERAGE_DIR="/tmp/libjpeg_coverage"
OUTPUT_DIR="/tmp/libjpeg_output"

# Tests to exclude (known failures)
EXCLUDE_TESTS="djpeg-shared-rgb-islow-icc-cmp|djpeg-static-rgb-islow-icc-cmp"

# This is the first time, we trace the unit tests
if [[ $SNAPSHOT_RTS -eq 1 && ! -d "$COVERAGE_DIR" ]]; then
    mkdir -p "$COVERAGE_DIR"

    # Run tests under Pin with coverage tracing
    # -dump_on_exit 1 is needed because libjpeg uses standalone test executables
    # (not create_test_sourcelist), so tests don't call pin_rts_dump_coverage()
    TEST_EXIT=0
    $PIN_ROOT/pin \
        -follow_execv \
        -t $PINTOOLS_RTS/obj-intel64/functrace.so \
        -runtime_dump \
        -logdir "$COVERAGE_DIR" \
        -libs 1 \
        -follow_child 1 \
        -dump_on_exit 1 \
        -- ctest -E "$EXCLUDE_TESTS" --output-on-failure || TEST_EXIT=$?

    # Process Coverage Data
    echo ""
    echo "=== Coverage Data ==="
    echo "Coverage directory: $COVERAGE_DIR"
    ls -la "$COVERAGE_DIR" | head -20

    # Convert coverage to CSV
    echo ""
    echo "=== Converting coverage to CSV ==="
    mkdir -p "$OUTPUT_DIR"

    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts convert \
        -i "$COVERAGE_DIR" \
        --regex '.*libjpeg.*|.*turbojpeg.*|.*jpeg.*|.*tj.*|/j[a-z]+\.[ch]|/rd[a-z]+\.[ch]|/wr[a-z]+\.[ch]|/transupp\.[ch]' \
        --repo "${SRC}/libjpeg-turbo" \
        -o "$OUTPUT_DIR" \
        cpp --ctest

    # Exit with test exit code
    exit $TEST_EXIT
fi

if [[ $RTS_ON -eq 1 ]]; then
    # This is subsequent test, select which ones to run
    SELECTION_DIR="/tmp/selection"
    rm -rf "$SELECTION_DIR"

    # Run binaryrts select with dirty/uncommitted changes
    PATCH=/tmp/patch.diff
    test -f $PATCH

    echo "=== Selecting unit tests ==="
    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts select \
        --repo $SRC/libjpeg-turbo \
        --diff $PATCH \
        --repo-state new \
        -o "$SELECTION_DIR" \
        cpp \
        --lookup "$OUTPUT_DIR/function-lookup.csv" \
        --traces "$OUTPUT_DIR/test-function-traces.csv"

    export INCLUDED_TESTS=$(poetry run binaryrts utils filter "$SELECTION_DIR/included.txt" -f ctest 2>/dev/null)
    echo "CTEST_FILTER=$INCLUDED_TESTS"

    # Return to build directory for ctest
    cd "$SRC/libjpeg-turbo/$BUILD_DIR"
    if [[ -n "$INCLUDED_TESTS" ]]; then
        ctest -R "$INCLUDED_TESTS" --output-on-failure
    else
        echo "No tests selected - all tests excluded by RTS"
    fi
else
    ctest -E "$EXCLUDE_TESTS" --output-on-failure
fi

exit $?
