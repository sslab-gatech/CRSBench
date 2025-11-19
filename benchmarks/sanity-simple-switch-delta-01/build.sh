#/bin/bash -eu

$CC $CFLAGS -c $SRC/simple-switch/simple.c -o $SRC/simple-switch/simple.o
for fuzzer in $(find $SRC/fuzz -name 'ossfuzz*.c'); do
    fname=$(basename $fuzzer)
    fuzzer_name=${fname%.*}
    fuzzer_obj=${fuzzer%.*}.o
    $CC $CFLAGS -I$SRC/simple-switch/ -c $fuzzer -o $fuzzer_obj
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_obj $SRC/simple-switch/simple.o -o $OUT/$fuzzer_name
done

cp -r $SRC/simple-switch $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    cp -r $SRC/.aixcc $OUT/.aixcc
fi
