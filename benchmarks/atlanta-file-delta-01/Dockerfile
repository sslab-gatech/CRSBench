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
RUN apt-get update && apt install -y make autoconf automake libtool shtool
RUN apt-get update && apt install -y libbz2-dev      liblzma-dev      zlib1g-dev      libzstd-dev      liblz4-dev
RUN apt-get update && apt install -y libbz2-dev:i386 liblzma-dev:i386 zlib1g-dev:i386 libzstd-dev:i386 liblz4-dev:i386 
#RUN git clone --depth 1 https://github.com/file/file.git
COPY pkgs/file.tar.gz $SRC/
RUN tar -xzf file.tar.gz && rm file.tar.gz

# Supplement file's existing test files
# RUN git clone --depth 1 https://github.com/DavidKorczynski/binary-samples.git
COPY pkgs/binary-samples.tar.gz $SRC/
RUN tar -xzf binary-samples.tar.gz && rm binary-samples.tar.gz
# RUN git clone --depth 1 https://github.com/corkami/pocs
COPY pkgs/pocs.tar.gz $SRC/
RUN tar -xzf pocs.tar.gz && rm pocs.tar.gz

WORKDIR file
COPY build.sh fuzzer_temp_file.h magic_fuzzer.cc magic_fuzzer_loaddb.cc magic_fuzzer_fd.cc magic_fuzzer_fd.options $SRC/
COPY .aixcc $SRC/.aixcc
