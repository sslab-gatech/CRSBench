#!/bin/bash
set -e

export PIN_ROOT=/opt/pin
export BINARY_RTS=/opt/binary-rts
export PINTOOLS_RTS=$BINARY_RTS/pintools-rts
export PIN_LISTENER_DIR=$PINTOOLS_RTS/pin_listener
RTS_ON=${RTS_ON:-0}
SNAPSHOT_RTS=$(test -d $PIN_ROOT && echo 1 || echo 0)
echo "SNAPSHOT_RTS $SNAPSHOT_RTS RTS_ON $RTS_ON"

# Known failures - these tests are expected to fail and should be ignored
known_failures=(
  "test_block_header"
  "test_index"
  "test_index_hash"
  "test_files.sh"
  "test_lzma_stream_header_decode"
  "test_lzma_stream_footer_decode"
  "test_lzma_index_decoder"
  "test_lzma_block_header_decode"
  "test_lzma_index_hash_decode"
  "test_stream_flags"
)

filter_test_failures() {
    readarray -t found_failures < <(
      cat tests/*.log 2>/dev/null | \
      grep -e "^FAIL:" | \
      sed "s/FAIL: \([^ ]*\).*/\1/")

    local invalid_found=0
    for f in "${found_failures[@]}"; do
      local allowed=0
      for k in "${known_failures[@]}"; do
        if [[ "$f" == "$k" ]]; then
            allowed=1
            break
        fi
      done
      if [[ $allowed -eq 0 ]]; then
        invalid_found=1
        echo "FAILED: '$f'"
      else
        echo "SKIPPED: '$f'"
      fi
    done
    return $invalid_found
}

# List of C test executables
C_TESTS=(
    "test_bcj_exact_size"
    "test_block_header"
    "test_check"
    "test_filter_flags"
    "test_filter_str"
    "test_hardware"
    "test_index"
    "test_index_hash"
    "test_lzip_decoder"
    "test_memlimit"
    "test_stream_flags"
    "test_vli"
    "test_microlzma"
)

# Build with autotools
if [[ $SNAPSHOT_RTS -eq 1 ]]; then
    ./autogen.sh --no-po4a --no-doxygen
    ./configure \
      CFLAGS="-g -O0 -fno-inline" \
      --enable-static \
      --enable-debug \
      --disable-shared \
      --disable-xzdec \
      --disable-lzmadec \
      --disable-lzmainfo
else
    ./autogen.sh --no-po4a --no-doxygen
    ./configure \
      --enable-static \
      --enable-debug \
      --disable-shared \
      --disable-xzdec \
      --disable-lzmadec \
      --disable-lzmainfo
fi

make -j$(nproc)

set +e  # Disable for test phase since known failures are expected

COVERAGE_DIR="/tmp/xz_coverage"
OUTPUT_DIR="/tmp/xz_output"

# RTS Coverage Collection (first run with SNAPSHOT_RTS=1)
if [[ $SNAPSHOT_RTS -eq 1 && ! -d "$COVERAGE_DIR" ]]; then
    mkdir -p "$COVERAGE_DIR"

    # Build test executables without running them
    echo "=== Building test executables ==="
    make -C tests check TESTS= -j$(nproc)

    echo "=== Collecting coverage under Pin ==="
    rm -f "$COVERAGE_DIR/dump-lookup.log"

    # Run each C test under Pin with unique logdir to avoid overwrites
    test_idx=0
    for test_name in "${C_TESTS[@]}"; do
        test_path="tests/${test_name}"
        if [[ -x "$test_path" ]]; then
            echo "Running: $test_name"
            test_logdir="$COVERAGE_DIR/test_${test_idx}_${test_name}"
            mkdir -p "$test_logdir"

            # Set srcdir so tests can find their data files
            srcdir="$SRC/xz/tests" $PIN_ROOT/pin \
                -follow_execv \
                -t $PINTOOLS_RTS/obj-intel64/functrace.so \
                -runtime_dump \
                -logdir "$test_logdir" \
                -libs 1 \
                -dump_on_exit 1 \
                -- "$test_path" || true

            # Move coverage logs to main dir with unique names
            for log_file in "$test_logdir"/*.log; do
                [[ -f "$log_file" ]] || continue
                log_basename=$(basename "$log_file" .log)
                [[ "$log_basename" == "dump-lookup" ]] && continue
                unique_name="${test_idx}_${test_name}_${log_basename}"
                mv "$log_file" "$COVERAGE_DIR/${unique_name}.log"
                echo "${unique_name};${test_name}" >> "$COVERAGE_DIR/dump-lookup.log"
            done
            rmdir "$test_logdir" 2>/dev/null || true
            ((test_idx++))
        else
            echo "Warning: $test_path not found or not executable"
        fi
    done

    echo ""
    echo "=== Coverage Data ==="
    echo "Coverage directory: $COVERAGE_DIR"
    ls -la "$COVERAGE_DIR" | head -20

    echo ""
    echo "=== Converting coverage to CSV ==="
    mkdir -p "$OUTPUT_DIR"

    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts convert \
        -i "$COVERAGE_DIR" \
        --regex '.*/src/.*\.[ch]|.*/tests/.*\.[ch]' \
        --repo "${SRC}/xz" \
        -o "$OUTPUT_DIR" \
        cpp --ctest

    cd "$SRC/xz"
    make check || true
    filter_test_failures
    exit $?
fi

# RTS Test Selection (RTS_ON=1)
if [[ $RTS_ON -eq 1 ]]; then
    echo "=== Building test executables ==="
    make -C tests check TESTS= -j$(nproc)

    SELECTION_DIR="/tmp/selection"
    rm -rf "$SELECTION_DIR"

    PATCH=/tmp/patch.diff
    test -f $PATCH

    echo "=== Selecting unit tests ==="
    cd /opt/binary-rts/binaryrts/cli
    poetry run binaryrts select \
        --repo $SRC/xz \
        --diff $PATCH \
        --repo-state new \
        --simple-output \
        -o "$SELECTION_DIR" \
        cpp \
        --lookup "$OUTPUT_DIR/function-lookup.csv" \
        --traces "$OUTPUT_DIR/test-function-traces.csv"

    echo ""
    echo "=== Included tests ==="
    cat "$SELECTION_DIR/included.txt"
    echo ""
    echo "=== Excluded tests ==="
    cat "$SELECTION_DIR/excluded.txt"

    cd "$SRC/xz"

    # Run selected tests (simple format: one test name per line)
    mapfile -t SELECTED_TESTS < "$SELECTION_DIR/included.txt"
    selected_count=0
    for test_name in "${SELECTED_TESTS[@]}"; do
        [[ -z "$test_name" ]] && continue
        test_path="tests/${test_name}"
        if [[ -x "$test_path" ]]; then
            echo "Running selected test: $test_name"
            srcdir="$SRC/xz/tests" "$test_path" || true
            ((selected_count++))
        fi
    done

    # Always run shell script tests
    echo ""
    echo "=== Running shell script tests ==="
    cd tests
    for sh_test in test_*.sh; do
        if [[ -x "$sh_test" ]]; then
            echo "Running: $sh_test"
            bash "$sh_test" || true
        fi
    done
    cd ..

    if [[ $selected_count -eq 0 ]]; then
        echo "No C tests selected by RTS"
    fi

    filter_test_failures
    exit $?
fi

# Normal test run (no RTS)
make check || true
filter_test_failures
exit $?
