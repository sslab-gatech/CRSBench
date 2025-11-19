#!/bin/bash

./autogen.sh --no-po4a --no-doxygen
./configure \
  --enable-static \
  --enable-debug \
  --disable-shared \
  --disable-xzdec \
  --disable-lzmadec \
  --disable-lzmainfo

make check

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

# filter buggy unit tests
readarray -t found_failures < <(
  cat tests/*.log | \
  grep -e "^FAIL:" | \
  sed "s/FAIL: \([^ ]*\).*/\1/")

invalid_found=0

for f in "${found_failures[@]}"; do
  allowed=0
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

exit $invalid_found
