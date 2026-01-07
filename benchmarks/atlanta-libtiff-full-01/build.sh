#!/bin/bash -eu
#
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cp ${SRC}/*.options ${OUT}/

# Build zlib (only if not already built)
if [ ! -f "$WORK/lib/libz.a" ]; then
    pushd "$SRC/zlib"
    ./configure --static --prefix="$WORK"
    make -j$(nproc) CFLAGS="$CFLAGS -fPIC"
    make install
    popd
fi

# Build libjpeg-turbo (only if not already built)
if [ ! -f "$WORK/lib/libjpeg.a" ]; then
    pushd "$SRC/libjpeg-turbo"
    cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DENABLE_STATIC=on -DENABLE_SHARED=off
    make -j$(nproc)
    make install
    popd
fi

# Build libjbig (only if not already built)
if [ ! -f "$WORK/lib/libjbig.a" ]; then
    pushd "$SRC/jbigkit"
    if [ "$ARCHITECTURE" = "i386" ]; then
        echo "#!/bin/bash" > gcc
        echo "clang -m32 \$*" >> gcc
        chmod +x gcc
        PATH=$PWD:$PATH make lib
    else
        make lib
    fi
    # Use cp instead of mv for incremental build support
    cp "$SRC"/jbigkit/libjbig/*.a "$WORK/lib/"
    cp "$SRC"/jbigkit/libjbig/*.h "$WORK/include/"
    popd
fi

if [ "$ARCHITECTURE" != "i386" ]; then
    apt-get install -y liblzma-dev 2>/dev/null || true
fi

# Build libtiff (only configure if not already done)
if [ ! -f Makefile ]; then
    cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DBUILD_SHARED_LIBS=off
fi
make -j$(nproc)
make install

if [ "$ARCHITECTURE" = "i386" ]; then
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba.cc -o $OUT/tiff_read_rgba \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_open.cc -o $OUT/tiff_open \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_from_user_buffer.cc -o $OUT/tiff_read_from_user_buffer \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_encoded_strip.cc -o $OUT/tiff_read_encoded_strip \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_raster_scanline_size.cc -o $OUT/tiff_raster_scanline_size \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba_tile_ext.cc -o $OUT/tiff_read_rgba_tile_ext \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include -I./port -I./libtiff \
        $SRC/libtiff/contrib/oss-fuzz/tiffinfo.cc -o $OUT/tiffinfo \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include -I./port -I./libtiff \
        $SRC/libtiff/contrib/oss-fuzz/tiffcp.cc -o $OUT/tiffcp \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
else
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba.cc -o $OUT/tiff_read_rgba \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_open.cc -o $OUT/tiff_open \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_from_user_buffer.cc -o $OUT/tiff_read_from_user_buffer \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_encoded_strip.cc -o $OUT/tiff_read_encoded_strip \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_raster_scanline_size.cc -o $OUT/tiff_raster_scanline_size \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
        $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba_tile_ext.cc -o $OUT/tiff_read_rgba_tile_ext \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include -I./port -I./libtiff \
        $SRC/libtiff/contrib/oss-fuzz/tiffinfo.cc -o $OUT/tiffinfo \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
    $CXX $CXXFLAGS -std=c++11 -I$WORK/include -I./port -I./libtiff \
        $SRC/libtiff/contrib/oss-fuzz/tiffcp.cc -o $OUT/tiffcp \
        $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
        $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -Wl,-Bstatic -llzma -Wl,-Bdynamic
fi

# dict and samples
[ -f $SRC/libtiff/contrib/oss-fuzz/tiff.dict ] && cp $SRC/libtiff/contrib/oss-fuzz/tiff.dict $OUT/ || true
find . -name "*.tif" | xargs zip $OUT/tiff_read_rgba_seed_corpus.zip || true
