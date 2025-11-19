#/bin/bash -eu

for fuzzer in $(find $SRC/fuzz -name '*_harness.c'); do
    fname=$(basename $fuzzer)
    fuzzer_name=${fname%.*}
    fuzzer_obj=${fuzzer%.*}.o
    $CC $CFLAGS -D ___TEST___ -c $fuzzer -o $fuzzer_obj
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_obj -o $OUT/$fuzzer_name
done

cp -r $SRC/cp-user-timeouts-and-crashes-src $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    cp -r $SRC/.aixcc $OUT/.aixcc
fi
