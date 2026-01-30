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

FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

RUN apt-get update && apt-get install -y make autoconf automake libtool cmake nasm
# RUN git clone git@github.com:Team-Atlanta/cp-c-libtiff.git libtiff
# RUN git clone --depth 1 https://github.com/madler/zlib
COPY pkgs/zlib.tar.gz $SRC/
RUN tar -xzf zlib.tar.gz && rm zlib.tar.gz
# RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
COPY pkgs/libjpeg-turbo.tar.gz $SRC/
RUN tar -xzf libjpeg-turbo.tar.gz && rm libjpeg-turbo.tar.gz
# RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit
COPY pkgs/jbigkit.tar.gz $SRC/
RUN tar -xzf jbigkit.tar.gz && rm jbigkit.tar.gz
ADD https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz afl_testcases.tgz
ADD https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/tiff.dict tiff.dict
WORKDIR libtiff
COPY build.sh $SRC/
COPY .aixcc $SRC/.aixcc
COPY tiffcp.options $SRC/tiffcp.options
COPY tiffcrop.options $SRC/tiffcrop.options