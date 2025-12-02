# !/bin/bash
set -ex

PROJECT_CFLAGS="-g -O0 -D_NO_STRING_INLINES -DFORTIFY_SOURCE=0 -fPIC"
PROJECT_LDFLAGS=""

if [[ -n "${CFLAGS}" ]]; then
  PROJECT_CFLAGS="${PROJECT_CFLAGS} ${CFLAGS}"
fi

if [[ -n "${LDFLAGS}" ]]; then
  PROJECT_LDFLAGS="${PROJECT_LDFLAGS} ${LDFLAGS}"
fi

rm -rf test_build; mkdir -p test_build; cd test_build;

cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER="${CC}" -DCMAKE_C_FLAGS_RELEASE="${PROJECT_CFLAGS}" -DCMAKE_EXE_LINKER_FLAGS_INIT="${PROJECT_LDFLAGS}" -DREQUIRE_SIMD=0 -DWITH_SIMD=0 ..

make -j`nproc`

# Run tests
ctest -j`nproc` -E "djpeg-shared-rgb-islow-icc-cmp|djpeg-static-rgb-islow-icc-cmp"