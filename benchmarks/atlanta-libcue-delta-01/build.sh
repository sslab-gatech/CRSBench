#!/bin/bash -eu

# Build libcue fuzzer (rewritten from internal oss-fuzz/build.sh for incremental builds)

# cd $WORK
# cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_FUZZER=ON -DCMAKE_BUILD_TYPE=Release $SRC/libcue
# make

# fuzzer_name=fuzz
# cp ${fuzzer_name} $OUT/${fuzzer_name}
# cp $SRC/libcue/oss-fuzz/cue.dict $OUT/${fuzzer_name}.dict

# find $SRC/libcue/t -iname "*.cue" | \
#      xargs zip $OUT/${fuzzer_name}_seed_corpus.zip
# find $SRC/libcue/oss-fuzz/corpus -iname "*.cue" | \Z
#      xargs zip $OUT/${fuzzer_name}_seed_corpus.zip

# echo -en "[libfuzzer]\nclose_fd_mask=2\ndetect_leaks=0\n" >$OUT/${fuzzer_name}.options


# Use build directory inside $SRC instead of $WORK to avoid CMake source path mismatch
# When $SRC changes (build.sh uses /built-src, test.sh uses /test-src), cmake
# will fail with "source does not match" error if we use shared $WORK
BUILD_DIR="$SRC/libcue_build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Only run cmake if not already configured
if [ ! -f Makefile ]; then
    cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_FUZZER=ON -DCMAKE_BUILD_TYPE=Release $SRC/libcue
fi
make -j$(nproc)

fuzzer_name=fuzz
cp ${fuzzer_name} $OUT/${fuzzer_name}
cp $SRC/libcue/oss-fuzz/cue.dict $OUT/${fuzzer_name}.dict

find $SRC/libcue/t -iname "*.cue" | \
     xargs zip $OUT/${fuzzer_name}_seed_corpus.zip
find $SRC/libcue/oss-fuzz/corpus -iname "*.cue" | \
     xargs zip $OUT/${fuzzer_name}_seed_corpus.zip

echo -en "[libfuzzer]\nclose_fd_mask=2\ndetect_leaks=0\n" >$OUT/${fuzzer_name}.options

rsync -a --delete $SRC/libcue/ $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi