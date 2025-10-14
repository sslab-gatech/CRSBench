cp ${SRC}/*.options ${OUT}/

cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DENABLE_STATIC:bool=on
make "-j$(nproc)"
make install

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libjpeg_turbo_fuzzer.cc -o $OUT/libjpeg_turbo_fuzzer \
    -lFuzzingEngine "$WORK/lib/libturbojpeg.a"

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libjpeg_cjpeg_fuzzer.cc -o $OUT/libjpeg_cjpeg_fuzzer \
    -lFuzzingEngine "$WORK/lib/libturbojpeg.a"

cp $SRC/libjpeg_turbo_fuzzer_seed_corpus.zip $OUT/