#/bin/bash -eu

SRC_DIR="$SRC/missing-vulnerabilities"

CFLAGS="$CFLAGS -fsanitize-address-field-padding=1"
CXXFLAGS="$CXXFLAGS -fsanitize-address-field-padding=1"

for c_file in "$SRC_DIR"/*.c; do
    if [ -f "$c_file" ]; then
        file_name=$(basename "$c_file")
        obj_name="${file_name%.c}.o"
        echo "  Compiling $file_name to $obj_name"
        $CC $CFLAGS -c "$c_file" -o "$SRC_DIR/$obj_name"
    fi
done

for cpp_file in "$SRC_DIR"/*.cpp; do
    if [ -f "$cpp_file" ]; then
        file_name=$(basename "$cpp_file")
        obj_name="${file_name%.cpp}.o"
        echo "  Compiling $file_name to $obj_name"
        $CXX $CXXFLAGS -c "$cpp_file" -o "$SRC_DIR/$obj_name"
    fi
done

OBJ_FILES="$SRC_DIR"/*.o

$CXX $CXXFLAGS -I$SRC_DIR -c $SRC/fuzz/fuzz.cpp -o $SRC/fuzz/fuzz.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz/fuzz.o  $OBJ_FILES -o $OUT/fuzz


cp -r $SRC_DIR $OUT/src
if [ "${CRS_TEST:-False}" == "True" ]; then
    cp -r $SRC/.aixcc $OUT/.aixcc
fi