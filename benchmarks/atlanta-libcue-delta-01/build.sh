#/bin/bash -eu

$SRC/libcue/oss-fuzz/build.sh

rsync -a --delete $SRC/libcue/ $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    rsync -a --delete $SRC/.aixcc/ $OUT/.aixcc
fi