#/bin/bash -eu

$CC -w -o $OUT/mock_vp $SRC/cp-user-babynote-src/mock_vp.c

$CC $CFLAGS -D ___TEST___ -c $SRC/fuzz/filein_harness.c -o filein_harness.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE filein_harness.o -o $OUT/filein_harness

rsync -a --delete $SRC/cp-user-babynote-src/ $OUT/src
cp $SRC/filein_harness.options $OUT/filein_harness.options
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi
