cp ${SRC}/*.options ${OUT}/

# Use out-of-source build to avoid CMake cache corruption on incremental builds
# Build directory is relative to $SRC to ensure each environment has independent build
BUILD_DIR="$SRC/libjpeg-turbo_build"
INSTALL_DIR="$SRC/libjpeg-turbo_install"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR"
cd "$BUILD_DIR"

# Only run cmake if not already configured
if [ ! -f Makefile ]; then
    cmake "$SRC/libjpeg-turbo" -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DENABLE_STATIC:bool=on
fi
make "-j$(nproc)"
make install

# Build fuzzers (include both install dir for jconfig.h and source dir for other headers)
$CXX $CXXFLAGS -std=c++11 -I"$INSTALL_DIR/include" -I"$SRC/libjpeg-turbo" \
    $SRC/libjpeg_turbo_fuzzer.cc -o $OUT/libjpeg_turbo_fuzzer \
    -lFuzzingEngine "$INSTALL_DIR/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I"$INSTALL_DIR/include" -I"$SRC/libjpeg-turbo" \
    $SRC/libjpeg_cjpeg_fuzzer.cc -o $OUT/libjpeg_cjpeg_fuzzer \
    -lFuzzingEngine "$INSTALL_DIR/lib/libturbojpeg.a"

cp $SRC/libjpeg_turbo_fuzzer_seed_corpus.zip $OUT/