#!/bin/bash
set -e

export PIN_ROOT=/opt/pin
export BINARY_RTS=/opt/binary-rts
export PINTOOLS_RTS=$BINARY_RTS/pintools-rts
export PIN_LISTENER_DIR=$PINTOOLS_RTS/pin_listener
RTS_ON=${RTS_ON:-0}
SNAPSHOT_RTS=$(test -d $PIN_ROOT && echo 1 || echo 0) # artifact of rts_init_c.py
echo "SNAPSHOT_RTS $SNAPSHOT_RTS RTS_ON $RTS_ON"

BUILD_DIR=build_test
mkdir -p ${BUILD_DIR}
pushd ${BUILD_DIR}


if [[ ! -f "CMakeCache.txt" ]]; then
    if [[ $SNAPSHOT_RTS -eq 1 ]]; then
        # Append -fno-inline to prevent inlining, needed for Pin function tracing
        export CFLAGS="${CFLAGS:-} -fno-inline"
        export CXXFLAGS="${CXXFLAGS:-} -fno-inline"
        cmake .. \
            -DBUILD_TESTING=1 \
            -DENABLE_PIN_LISTENER=ON \
            -DCMAKE_BUILD_TYPE=Debug
    else
        cmake .. -DBUILD_TESTING=1
    fi
fi

make all -j$(nproc)

COVERAGE_DIR="/tmp/freerdp_coverage"
OUTPUT_DIR="/tmp/freerdp_output"

# This is the first time, we trace the unit tests
if [[ $SNAPSHOT_RTS -eq 1 && ! -d "$COVERAGE_DIR" ]]; then
    mkdir -p "$COVERAGE_DIR"

    # Run test under Pin with coverage tracing
    TEST_EXIT=0
    $PIN_ROOT/pin \
        -follow_execv \
        -t $PINTOOLS_RTS/obj-intel64/functrace.so \
        -runtime_dump \
        -logdir "$COVERAGE_DIR" \
        -libs 1 \
        -follow_child 1 \
        -- ctest -E "TestSynchCritical|TestFreeRDPCodecH264" --output-on-failure || TEST_EXIT=$?

    # Process Coverage Data
    echo ""
    echo "=== Coverage Data ==="
    echo "Coverage directory: $COVERAGE_DIR"
    ls -la "$COVERAGE_DIR"

    # Convert coverage to CSV
    echo ""
    echo "=== Converting coverage to CSV ==="
    mkdir -p OUTPUT_DIR

    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts convert \
           -i "$COVERAGE_DIR" \
           --regex '.*freerdp.*' \
           --repo "${SRC}/FreeRDP" \
           -o "$OUTPUT_DIR" \
           cpp --ctest

    # Exit with exit code
    exit $TEST_EXIT
fi

if [[ $RTS_ON -eq 1 ]]; then
    # This is subsequent test, select which ones to test
    SELECTION_DIR="/tmp/selection"
    rm -rf "$SELECTION_DIR"
    
    # Run binaryrts select with dirty/uncommitted changes
    PATCH=/tmp/patch.diff
    test -f $PATCH
    
    echo "=== Selecting unit tests ==="
    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts select \
           --repo $SRC/FreeRDP \
           --diff $PATCH \
           --repo-state new \
           -o "$SELECTION_DIR" \
           cpp \
           --lookup "$OUTPUT_DIR/function-lookup.csv" \
           --traces "$OUTPUT_DIR/test-function-traces.csv"

    export INCLUDED_TESTS=$(poetry run binaryrts utils filter "$SELECTION_DIR/included.txt" -f ctest 2>/dev/null)
    echo "CTEST_FILTER=$INCLUDED_TESTS"

    # Return to build directory for ctest
    cd "$SRC/FreeRDP/$BUILD_DIR"
    ctest -R "$INCLUDED_TESTS" --output-on-failure
else
    ctest -E "TestSynchCritical|TestFreeRDPCodecH264"
fi

exit $?
