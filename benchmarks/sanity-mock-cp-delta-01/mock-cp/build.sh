#/bin/bash -eu


$CC $CFLAGS -D ___TEST___ -c $SRC/fuzz/filein_harness.c -o filein_harness.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE filein_harness.o -o $OUT/filein_harness

rsync -a --delete $SRC/mock-cp-src/ $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi