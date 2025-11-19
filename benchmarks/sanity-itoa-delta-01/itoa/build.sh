#/bin/bash -eu

$CC -w -o $OUT/mock_vp $SRC/cp-user-itoa/mock_vp.c

$CC $CFLAGS -D ___TEST___ -c $SRC/fuzz/filein_harness.c -o filein_harness.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE filein_harness.o -o $OUT/filein_harness

rsync -a --delete $SRC/cp-user-itoa/ $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi