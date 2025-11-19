#!/bin/bash

MAVEN_ARGS="-Drat.skip=true -Dcheckstyle.skip=true"
if [ -z "${MVN}" ]; then
        MVN=mvn
fi

$MVN clean test $MAVEN_ARGS
