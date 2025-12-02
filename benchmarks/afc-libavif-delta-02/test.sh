#!/bin/bash

set -eu
cd $SRC/libavif



# Build dav1d with sanitizer flags.
# Adds extra flags: -Db_sanitize=$SANITIZER -Db_lundef=false, and -Denable_asm=false for msan
# DAV1D_EXTRA_FLAGS=""
# if [[ "$SANITIZER" != "coverage" && "$SANITIZER" != "introspector" ]]; then
#   DAV1D_EXTRA_FLAGS="${DAV1D_EXTRA_FLAGS} -Db_sanitize=$SANITIZER -Db_lundef=false"
# fi
# if [[ "$SANITIZER" == "memory" ]]; then
#   DAV1D_EXTRA_FLAGS="${DAV1D_EXTRA_FLAGS} -Denable_asm=false"
# fi
# sed -i "s/meson setup \(.*\) \.\./meson setup \1${DAV1D_EXTRA_FLAGS} ../g" ./ext/dav1d.cmd

# Build libaom with sanitizer flags.
# Adds extra flags: -DAOM_TARGET_CPU=generic for msan.
if [[ "$SANITIZER" == "memory" ]]; then
  sed -i 's/cmake \(.*\) \.\./cmake \1 -DAOM_TARGET_CPU=generic ../g' ./ext/aom.cmd
fi

# Build libjpeg-turbo with sanitizer flags. Add extra flag -DWITH_SIMD=0 for msan.
# See https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/README.md#memory-debugger-pitfalls
if [[ "$SANITIZER" == "memory" ]]; then
  sed -i 's/cmake -S libjpeg-turbo \(.*\)/cmake -S libjpeg-turbo \1 -DWITH_SIMD=0/g' ./ext/libjpeg.cmd
fi

# Prepare dependencies.
cd ext && bash aom.cmd && bash dav1d.cmd && bash fuzztest.cmd && bash libjpeg.cmd &&
      bash libsharpyuv.cmd && bash libyuv.cmd && bash zlibpng.cmd || true
  
cd ..

# build libavif
mkdir -p build
cd build
EXTRA_CMAKE_FLAGS=""
if [[ "$FUZZING_ENGINE" == "libfuzzer" ]]; then
  CXXFLAGS="${CXXFLAGS} -DFUZZTEST_COMPATIBILITY_MODE"
  EXTRA_CMAKE_FLAGS="${EXTRA_CMAKE_FLAGS} -DAVIF_ENABLE_FUZZTEST=ON -DFUZZTEST_COMPATIBILITY_MODE=libfuzzer"
fi
cmake .. -G Ninja -DBUILD_SHARED_LIBS=OFF -DAVIF_CODEC_AOM=LOCAL -DAVIF_CODEC_DAV1D=LOCAL \
      -DAVIF_CODEC_AOM_DECODE=ON -DAVIF_CODEC_AOM_ENCODE=ON \
      -DAVIF_LOCAL_FUZZTEST=ON -DAVIF_BUILD_TESTS=ON -DAVIF_GTEST=LOCAL \
      -DAVIF_JPEG=LOCAL -DAVIF_LIBSHARPYUV=LOCAL \
      -DAVIF_LIBYUV=OFF -DAVIF_ZLIBPNG=LOCAL -DAVIF_BUILD_APPS=ON \
      -DAVIF_BUILD_TESTS=ON -DAVIF_ENABLE_WERROR=ON \
      ${EXTRA_CMAKE_FLAGS}

ninja
ctest . -j $(nproc) -E avifallocationtest
./avifdec -u spill ../tests/data/lines.avif ../tests/data/linetest.png
diff ../tests/data/linetest.png ../tests/data/lines_spill.png