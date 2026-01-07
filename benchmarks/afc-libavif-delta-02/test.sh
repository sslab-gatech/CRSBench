#!/bin/bash
set -e

export PIN_ROOT=/opt/pin
export BINARY_RTS=/opt/binary-rts
export PINTOOLS_RTS=$BINARY_RTS/pintools-rts
export PIN_LISTENER_DIR=$PINTOOLS_RTS/pin_listener
RTS_ON=${RTS_ON:-0}
SNAPSHOT_RTS=$(test -d $PIN_ROOT && echo 1 || echo 0)
echo "SNAPSHOT_RTS $SNAPSHOT_RTS RTS_ON $RTS_ON"

cd $SRC/libavif

# Build libaom with sanitizer flags. Add extra flag -DAOM_TARGET_CPU=generic for msan.
if [[ "$SANITIZER" == "memory" ]]; then
  sed -i 's/cmake \(.*\) \.\./cmake \1 -DAOM_TARGET_CPU=generic ../g' ./ext/aom.cmd
fi

# Build libjpeg-turbo with sanitizer flags. Add extra flag -DWITH_SIMD=0 for msan.
if [[ "$SANITIZER" == "memory" ]]; then
  sed -i 's/cmake -S libjpeg-turbo \(.*\)/cmake -S libjpeg-turbo \1 -DWITH_SIMD=0/g' ./ext/libjpeg.cmd
fi

# Prepare dependencies (libyuv excluded - using AVIF_LIBYUV=OFF)
# Skip cloning if directories already exist (from docker snapshot)
cd ext
[[ -d aom ]] || bash aom.cmd
[[ -d dav1d ]] || bash dav1d.cmd
[[ -d fuzztest ]] || bash fuzztest.cmd
[[ -d libjpeg-turbo ]] || bash libjpeg.cmd
[[ -d libwebp ]] || bash libsharpyuv.cmd
[[ -d zlib ]] || bash zlibpng.cmd
cd ..

# Build libavif
BUILD_DIR=build
mkdir -p $BUILD_DIR
cd $BUILD_DIR

COVERAGE_DIR="/tmp/libavif_coverage"
OUTPUT_DIR="/tmp/libavif_output"

if [[ ! -f "CMakeCache.txt" ]]; then
    EXTRA_CMAKE_FLAGS=""
    if [[ $SNAPSHOT_RTS -eq 1 ]]; then
        # Append -fno-inline to prevent inlining, needed for Pin function tracing
        export CFLAGS="${CFLAGS:-} -fno-inline"
        export CXXFLAGS="${CXXFLAGS:-} -fno-inline"
        EXTRA_CMAKE_FLAGS="-DENABLE_PIN_LISTENER=ON -DCMAKE_BUILD_TYPE=Debug"
    fi
    if [[ "$FUZZING_ENGINE" == "libfuzzer" ]]; then
        CXXFLAGS="${CXXFLAGS} -DFUZZTEST_COMPATIBILITY_MODE"
        EXTRA_CMAKE_FLAGS="${EXTRA_CMAKE_FLAGS} -DAVIF_ENABLE_FUZZTEST=ON -DFUZZTEST_COMPATIBILITY_MODE=libfuzzer"
    fi
    cmake .. -G Ninja \
        -DBUILD_SHARED_LIBS=OFF \
        -DAVIF_CODEC_AOM=LOCAL \
        -DAVIF_CODEC_DAV1D=LOCAL \
        -DAVIF_CODEC_AOM_DECODE=ON \
        -DAVIF_CODEC_AOM_ENCODE=ON \
        -DAVIF_LOCAL_FUZZTEST=ON \
        -DAVIF_GTEST=LOCAL \
        -DAVIF_JPEG=LOCAL \
        -DAVIF_LIBSHARPYUV=LOCAL \
        -DAVIF_LIBYUV=OFF \
        -DAVIF_ZLIBPNG=LOCAL \
        -DAVIF_BUILD_APPS=ON \
        -DAVIF_BUILD_TESTS=ON \
        -DAVIF_ENABLE_WERROR=ON \
        ${EXTRA_CMAKE_FLAGS}
fi

ninja

# First run with Pin: trace tests and collect coverage
if [[ $SNAPSHOT_RTS -eq 1 && ! -d "$COVERAGE_DIR" ]]; then
    mkdir -p "$COVERAGE_DIR"

    echo ""
    echo "=== Running tests under Pin with coverage tracing ==="

    TEST_EXIT=0
    $PIN_ROOT/pin \
        -follow_execv \
        -t $PINTOOLS_RTS/obj-intel64/functrace.so \
        -runtime_dump \
        -logdir "$COVERAGE_DIR" \
        -libs 1 \
        -follow_child 1 \
        -- ctest . -j1 -E "avifallocationtest|avifyuv" --output-on-failure || TEST_EXIT=$?

    echo ""
    echo "=== Coverage Results ==="
    ls -la "$COVERAGE_DIR" | head -20

    # Convert coverage to CSV
    echo ""
    echo "=== Converting coverage to CSV ==="
    mkdir -p "$OUTPUT_DIR"

    cd $BINARY_RTS/binaryrts/cli
    # Note: Do NOT use --ctest flag - it breaks gtest filtering
    # Use regex to include only libavif source files
    poetry run binaryrts convert \
        -i "$COVERAGE_DIR" \
        --regex '.*/src/.*|.*/include/.*|.*/apps/.*' \
        --repo "$SRC/libavif" \
        -o "$OUTPUT_DIR" \
        cpp

    echo ""
    echo "=== Output files ==="
    ls -la "$OUTPUT_DIR"
    echo "Total tests: $(wc -l < "$OUTPUT_DIR/test-lookup.csv")"

    exit $TEST_EXIT
fi

# RTS mode: select tests based on patch
if [[ $RTS_ON -eq 1 ]]; then
    SELECTION_DIR="/tmp/selection"
    rm -rf "$SELECTION_DIR"

    PATCH=/tmp/patch.diff
    test -f $PATCH

    echo "=== Selecting tests based on patch ==="
    cd $BINARY_RTS/binaryrts/cli
    poetry run binaryrts select \
        --repo "$SRC/libavif" \
        --diff "$PATCH" \
        --repo-state new \
        -o "$SELECTION_DIR" \
        cpp \
        --lookup "$OUTPUT_DIR/function-lookup.csv" \
        --traces "$OUTPUT_DIR/test-function-traces.csv"

    INCLUDED=$(cat "$SELECTION_DIR/included.txt" 2>/dev/null | grep -v '^$' | wc -l)
    EXCLUDED=$(cat "$SELECTION_DIR/excluded.txt" 2>/dev/null | grep -v '^$' | wc -l)
    TOTAL=$((INCLUDED + EXCLUDED))
    echo "[RTS] Total: $TOTAL"
    echo "[RTS] Selected: $INCLUDED"
    echo "[RTS] Excluded: $EXCLUDED"

    cd "$SRC/libavif/$BUILD_DIR"

    if [[ "$INCLUDED" -eq 0 ]]; then
        echo "No tests selected - all tests excluded!"
        exit 0
    elif [[ "$EXCLUDED" -eq 0 ]]; then
        echo "All tests selected - running without filter"
        ctest -E "avifallocationtest|avifyuv" --output-on-failure
    else
        # Use file-based excludes to avoid "Argument list too long"
        export GTEST_EXCLUDES_FILE="$SELECTION_DIR/excluded.txt"
        echo "Using GTEST_EXCLUDES_FILE ($EXCLUDED tests excluded)"
        ctest -E "avifallocationtest|avifyuv" --output-on-failure
    fi
else
    # Normal test run (no RTS)
    ctest . -j $(nproc) -E "avifallocationtest|avifyuv" --output-on-failure
fi

# Run the decode spill test (only if avifdec was built)
if [ -f ./avifdec ]; then
    ./avifdec -u spill ../tests/data/lines.avif ../tests/data/linetest.png
    diff ../tests/data/linetest.png ../tests/data/lines_spill.png
else
    echo "avifdec not found, skipping spill test"
fi

exit 0
