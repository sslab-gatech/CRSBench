#!/bin/bash -euo pipefail
# Copyright 2021 Google LLC
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
# Search "UPDATE ME FOR NEW CP" for new CP preparation
#

# =========================================
# Variables
# =========================================

fuzzers=(
    # UPDATE ME FOR NEW CP
    "com.aixcc.pac4j.harnesses.one.Pac4jOne"
)

# UPDATE ME FOR NEW CP
proj_dir="$SRC/src/cp-java-pac4j-source"

driver_dir="$SRC/src/fuzz"
driver_jars_dir="$OUT/jars"

# =========================================
# Functions
# =========================================

build_proj() {
    # UPDATE ME FOR NEW CP

    set +u
    source $HOME/.sdkman/bin/sdkman-init.sh
    set -u

    cd "$proj_dir"
    mvn -DskipTests -Dgpg.skip clean -pl pac4j-core -am package install
}

build_driver_jars() {
    # UPDATE ME FOR NEW CP

    cd "$driver_dir"
    mvn clean verify
}

copy_fuzzer_jars() {
    # UPDATE ME FOR NEW CP

    local fuzzer="$1"
    local fuzzer_num="$2"
    local out_dir="$3"

    local jar_source="$driver_dir/pac4j-harness-${fuzzer_num}/target/pac4j-harness-${fuzzer_num}-1.0.0-SNAPSHOT.jar"
    local jar_dest="$out_dir/pac4j-harness-${fuzzer_num}.jar"
    local lib_source_dir="$driver_dir/pac4j-harness-${fuzzer_num}/target/lib/"

    if ! cp "$jar_source" "$jar_dest"; then
        echo "Can't copy JAR for ${fuzzer_num}"
        exit 1
    fi

    if ! cp "$lib_source_dir"* "$out_dir/"; then
        echo "Can't copy libs for ${fuzzer_num}"
        exit 1
    fi
}

copy_jars_to_out() {
    rm -rf "$driver_jars_dir"

    for fuzzer in "${fuzzers[@]}"; do
        fuzzer_num="${fuzzer%.*}"
        fuzzer_num="${fuzzer_num##*.}"
        fuzz_jar_dir="$driver_jars_dir/$fuzzer_num"

        rm -rf "$fuzz_jar_dir"
        mkdir -p "$fuzz_jar_dir"

        copy_fuzzer_jars "$fuzzer" "$fuzzer_num" "$fuzz_jar_dir"
    done
}

generate_driver_scripts() {
    for fuzzer in "${fuzzers[@]}"; do
        fuzzer_num="${fuzzer%.*}"
        fuzzer_num="${fuzzer_num##*.}"
        fuzzer_basename="${fuzzer##*.}"

        runtime_classpath=$(cd "$OUT"; find "./jars/$fuzzer_num" -name '*.jar' | xargs printf -- "\$this_dir/%s:")
        runtime_classpath="$runtime_classpath.:\$this_dir"

        script_path="$OUT/$fuzzer_basename"

        cat > "$script_path" <<EOF
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]; then
    mem_settings='-Xmx4096m:-Xss1024k:-rss_limit_mb=4096'
else
    mem_settings='-Xmx4096m:-Xss1024k:-rss_limit_mb=4096'
fi
LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":\$this_dir \\
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \\
--cp=$runtime_classpath \\
--target_class=$fuzzer \\
--jvm_args="\$mem_settings" \\
\$@
EOF

        chmod +x "$script_path"
    done
}

post_build() {
   rsync -a --delete "$SRC/src/" "$OUT/src"
    if [ "${CRS_TEST:-False}" == "True" ]; then
        rsync -a --delete "$SRC/.aixcc/" "$OUT/.aixcc"
    fi
}

# =========================================
# Main 
# =========================================

build_proj
build_driver_jars
copy_jars_to_out
generate_driver_scripts
post_build
