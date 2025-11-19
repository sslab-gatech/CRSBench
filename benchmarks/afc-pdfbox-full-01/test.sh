#!/bin/bash

MAVEN_ARGS="-Djacoco.skip=true -Drat.skip=true -Dcheckstyle.skip=true -Djavac.target.version=11 \
    -Dsurefire.failIfNoSpecifiedTests=false \
	-Dtest=!TestCreateSignature"

if [ -z "${MVN}" ]; then
	MVN=mvn
fi

$MVN test $MAVEN_ARGS