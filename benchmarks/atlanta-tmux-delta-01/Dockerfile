# Copyright 2020 Google LLC
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
RUN apt-get update && apt-get install -y autoconf automake bison pkg-config \
    ncurses-dev libtool

# RUN git clone https://github.com/libevent/libevent.git && \
COPY pkgs/libevent.tar.gz $SRC/
RUN tar -xzf libevent.tar.gz && rm libevent.tar.gz && \
    cd libevent && \
    mkdir build && \
    cd build && \
    cmake -DEVENT__DISABLE_MBEDTLS=ON -DEVENT__DISABLE_OPENSSL=ON -DEVENT__DISABLE_TESTS=ON -DEVENT__LIBRARY_TYPE=STATIC ../ && \
    make && make install

# RUN git clone --depth 1 git@github.com:Team-Atlanta/cp-c-tmux.git
# RUN git clone --depth 1 https://github.com/tmux/tmux-fuzzing-corpus.git
COPY pkgs/tmux-fuzzing-corpus.tar.gz $SRC/
RUN tar -xzf tmux-fuzzing-corpus.tar.gz && rm tmux-fuzzing-corpus.tar.gz
WORKDIR tmux
COPY build.sh $SRC/
