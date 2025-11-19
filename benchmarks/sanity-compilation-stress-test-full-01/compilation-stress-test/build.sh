#/bin/bash -eu
pushd $SRC/cp-user-compilation-stress-test-src
./build.sh
cp basic_fuzzer $OUT
popd

cp -r $SRC/cp-user-compilation-stress-test-src $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    cp -r $SRC/.aixcc $OUT/.aixcc
fi

