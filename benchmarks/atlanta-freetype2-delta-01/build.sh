#!/bin/bash -eux
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


cd $SRC/freetype2
rm -rf .git
rm -rf .gitmodules
rm -rf .gitignore
rm -rf subprojects/dlg
git init
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git config --global --add safe.directory "$(pwd)"
git add -f .
git commit -m "Base commit"
git submodule add https://github.com/nyorain/dlg.git subprojects/dlg 
git commit -m "Add subprojects/dlg"


cd $SRC/freetype2-testing
# Replace the freetype2 submodule with our challenge project source
rm -rf external/freetype2
cp -r $SRC/freetype2 $SRC/freetype2-testing/external/freetype2
# Skip git submodule update for freetype2 (line 21) since we provide it directly
sed -i '21d' $SRC/freetype2-testing/fuzzing/scripts/build/freetype.sh

# Tell CMake what fuzzing engine to link:
export CMAKE_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"

bash "fuzzing/scripts/build-fuzzers.sh"
bash "fuzzing/scripts/prepare-oss-fuzz.sh"

# Rename the `legacy' target to `ftfuzzer' for historical reasons:
for f in "${OUT}/legacy"*; do
    mv "${f}" "${f/legacy/ftfuzzer}"
done

zip -ju "${OUT}/ftfuzzer_seed_corpus.zip" "${SRC}/font-corpus/"*
