#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Run build script from the mosquitto repo
# ./fuzzing/scripts/oss-fuzz-build.sh

# Build direct broker dependency - cJSON
# Note that other dependencies, i.e. sqlite are not yet built because they are
# only used by plugins and not currently otherwise used.
MAKE_FLAGS="-j$(nproc)" # for local testing only
# MAKE_FLAGS=""
cd ${SRC}/cJSON
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF -DCMAKE_C_FLAGS=-fPIC . > /dev/null
make $MAKE_FLAGS > /dev/null
make install > /dev/null

# Build broker and library static libraries
cd ${SRC}/cp-c-mosquitto-src
make $MAKE_FLAGS WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_FUZZING=yes WITH_EDITLINE=no > /dev/null