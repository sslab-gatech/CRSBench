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

if [ ! -d subprojects/dlg/src ]; then
    rm -rf .git
    rm -rf .gitmodules
    rm -rf .gitignore
    rm -rf subprojects/dlg
    git init
    git config --global user.email "you@example.com"
    git config --global user.name "Your Name"
    git add -f .
    git commit -m "Base commit"
    git submodule add https://github.com/nyorain/dlg.git subprojects/dlg
    git commit -m "Add subprojects/dlg"
fi

cd $SRC/freetype2-testing

if [ ! -d external/freetype2/src  ]; then
    git submodule deinit -f external/freetype2
    rm -rf external/freetype2
    rm -rf .git/modules/external/freetype2
    cp -r $SRC/freetype2 $SRC/freetype2-testing/external/freetype2
    sed -i '21d' $SRC/freetype2-testing/fuzzing/scripts/build/freetype.sh
else
    if [ -s /tmp/patch.diff ]; then
        pushd external/freetype2
        git.real apply /tmp/patch.diff
        git add -f .
        git config --global user.email "you@example.com"
        git config --global user.name "Your Name"
        git commit -m "Apply patch"
        sleep infinity
        popd
    else
        echo "No patch file found at /tmp/patch.diff or it is empty. Skipping git apply."
    fi
fi

# Tell CMake what fuzzing engine to link:
export CMAKE_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"

bash "fuzzing/scripts/build-fuzzers.sh"
bash "fuzzing/scripts/prepare-oss-fuzz.sh"

# Rename the `legacy' target to `ftfuzzer' for historical reasons:
# Use cp instead of mv for incremental build support
for f in "${OUT}/legacy"*; do
    cp "${f}" "${f/legacy/ftfuzzer}"
done

zip -ju "${OUT}/ftfuzzer_seed_corpus.zip" "${SRC}/font-corpus/"*
