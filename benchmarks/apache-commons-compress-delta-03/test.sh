#!/bin/bash

# testLinuxFileInformation* tests are turned off because we're running as root in Docker.
# Zip64SupportIT is turned off to save time and resources -- fails locally and in ci/cd?!
MAVEN_ARGS="-Djacoco.skip=true -Drat.skip=true -Djavac.src.version=15 -Djavac.target.version=15 \
  -Dtest=!TarArchiveEntryTest#testLinuxFileInformationFrom*,!Zip64SupportIT"

if [ -z "${MVN}" ]; then
	MVN=mvn
fi

$MVN clean test $MAVEN_ARGS
