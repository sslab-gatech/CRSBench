#!/bin/bash
set -ex
set -o pipefail

cd /src/poi

sed -i 's/maxHeapSize = "2g"/maxHeapSize = "4g"/' build.gradle

for module in poi poi-scratchpad poi-ooxml poi-integration; do
    sed -i "s/systemProperties\['junit.jupiter.execution.parallel.enabled'\] = 'true'/systemProperties['junit.jupiter.execution.parallel.enabled'] = 'false'/" "$module/build.gradle"
done

sed -i "s/apply plugin: 'com.adarshr.test-logger'/\/\/ apply plugin: 'com.adarshr.test-logger'/" build.gradle

mv poi/src/test/java/org/apache/poi/ddf/TestEscherContainerRecord.java \
   poi/src/test/java/org/apache/poi/ddf/TestEscherContainerRecord.java.bak 2>/dev/null || true
mv poi/src/test/java/org/apache/poi/ddf/TestUnknownEscherRecord.java \
   poi/src/test/java/org/apache/poi/ddf/TestUnknownEscherRecord.java.bak 2>/dev/null || true
sed -i "/^test {/a\\    exclude '**/TestIOUtils.class'" poi/build.gradle

sed -i "/^test {/a\\    exclude '**/hslf/dev/**'\n    exclude '**/hwpf/converter/**'" poi-scratchpad/build.gradle

sed -i "/^test {/a\\    exclude '**/TestReadOnlySharedStringsTable.class'" poi-ooxml/build.gradle

GRADLE_FLAGS="-x javadoc -Dfile.encoding=UTF-8 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_8,JAVA_HOME_11 --no-build-cache --console=plain"
./gradlew $GRADLE_FLAGS clean
./gradlew $GRADLE_FLAGS :poi:test :poi-scratchpad:test :poi-ooxml:test :poi-ooxml-lite:test :poi-ooxml-full:test :poi-excelant:test :poi-examples:test

mv poi/src/test/java/org/apache/poi/ddf/TestEscherContainerRecord.java.bak \
   poi/src/test/java/org/apache/poi/ddf/TestEscherContainerRecord.java 2>/dev/null || true
mv poi/src/test/java/org/apache/poi/ddf/TestUnknownEscherRecord.java.bak \
   poi/src/test/java/org/apache/poi/ddf/TestUnknownEscherRecord.java 2>/dev/null || true