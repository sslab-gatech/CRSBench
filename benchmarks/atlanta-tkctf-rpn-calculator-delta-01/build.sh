#/bin/bash -eu

for fuzzer in $(find $SRC/fuzz -name '*_harness.c'); do
    fname=$(basename $fuzzer)
    fuzzer_name=${fname%.*}
    fuzzer_obj=${fuzzer%.*}.o
    $CC $CFLAGS -D __OSSFUZZ__ -c $fuzzer -o $fuzzer_obj
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_obj -o $OUT/$fuzzer_name
done

cp -r $SRC/cp-tkctf-rpn-calculator-source $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    cp -r $SRC/.aixcc $OUT/.aixcc
fi