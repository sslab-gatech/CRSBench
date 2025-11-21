#!/bin/bash

GRADLE_FLAGS="-x javadoc -Dfile.encoding=UTF-8 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_8,JAVA_HOME_11 --no-build-cache --console=plain"
echo "pwd: $(pwd)"
./gradlew $GRADLE_FLAGS clean  :poi:test :poi-scratchpad:test :poi-ooxml:test  :poi-ooxml-lite:test :poi-ooxml-full:test :poi-excelant:test :poi-examples:test
