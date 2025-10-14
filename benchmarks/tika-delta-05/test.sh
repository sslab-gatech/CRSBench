#!/bin/bash

# turn off some of the longer running tests
MAVEN_ARGS="-Djacoco.skip=true -Drat.skip=true -Dossindex.skip -Dcheckstyle.skip=true -Dsurefire.failIfNoSpecifiedTests=false \
  -Dtest=!TestChmExtraction,!OOXMLParserTest.testMultiThreaded,!TikaIT"

if [ -z "${MVN}" ]; then
        MVN=mvn
fi

$MVN clean test $MAVEN_ARGS -am -pl :tika-app
