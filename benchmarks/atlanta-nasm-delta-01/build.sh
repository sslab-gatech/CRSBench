#!/bin/bash
build_nasm() {
pushd .
    cd $SRC/cp-c-nasm-src
    # [ -d .git ] && git reset --hard && git clean -xdf
    ./autogen.sh
    ./configure
    make nasm
popd
}

build_libfuzzer() {
pushd .
    cd $SRC/cp-c-nasm-src
    mkdir -p fuzz
    cp $SRC/fuzz_* fuzz/
    cd $SRC/cp-c-nasm-src
    $CC $CFLAGS -std=c17 -DHAVE_CONFIG_H -I. -I. -I./include -I./include -I./x86 -I./x86 -I./asm -I./asm -I./disasm -I./disasm -I./output -I./output -I./fuzz -o fuzz/fuzz_nasm $LIB_FUZZING_ENGINE fuzz/fuzz_nasm.c  $SRC/cp-c-nasm-src/libnasm.a
    cp fuzz/fuzz_nasm $OUT/
popd
}


build_nasm
build_libfuzzer # libfuzzer only
cp $SRC/fuzz_nasm.options $OUT/
