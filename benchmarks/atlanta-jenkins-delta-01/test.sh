#!/bin/bash

# This performs the CP-specific tests. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set +u
source $HOME/.sdkman/bin/sdkman-init.sh
set -u

set -e
set -o pipefail

# set parallel value
: "${NPROC_VAL:=$(nproc)}"

HAS_FAILURE=false
FAILURE_STRING=''
ANY_TESTS_RUN=false

STDOUT_FILE=/tmp/stdout.txt

warn() {
  echo "$*" >&2
}

die() {
  warn "$*"
  exit 1
}
#report that there were test failures, exit value=1
report_test_failure() {
    echo "${FAILURE_STRING}"
    exit 2
}

all_good() {
    echo "tests all passed!"
    exit 0
}


evalRetVal() {
  retval=$1
  testName=$2
  if [ $retval -eq 1 ]; then
    if grep -q "There are test failures" ${STDOUT_FILE}; then
      HAS_FAILURE=true
      FAILURE_STRING+="test failures for $testName exit=$retval; "
      ANY_TESTS_RUN=true
      echo
    elif
      grep -q "BUILD FAILURE" ${STDOUT_FILE}; then
        die "build failure on $testName"
    else
      die "mvn exit=1, not clear why?!"
    fi
  elif [ $retval -eq 0 ]; then
    if grep -q "Results" ${STDOUT_FILE} && grep -q "BUILD SUCCESS" ${STDOUT_FILE}; then
      echo "tests pass for $testName exit=$retval"
      ANY_TESTS_RUN=true
    elif grep -q "No tests to run." ${STDOUT_FILE}; then
      echo "no tests run for $testName"
    else
      die "exit=0, but did not find test results?!"
    fi
  else
      die "mvn process failed. exit=$retval for $testName"
  fi
}

rmStdout() {
  if [ -f ${STDOUT_FILE} ]; then
    rm ${STDOUT_FILE} || die "couldn't remove stdout";
  fi
}

rmStdout

cd ${SRC}/src/jenkins && \
mvn -DskipTests -Pquick-build -am -pl bom,war install || exit 1

retval=0
cd ${SRC}/src/plugins/pipeline-util-plugin && \
mvn -T${NPROC_VAL} surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "pipeline-util-plugin"

rmStdout

retval=0
cd ${SRC}/src/plugins/toy-plugin && \
mvn -T${NPROC_VAL} surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "toy-plugin"

rmStdout

retval=0
cd ${SRC}/src/plugins/code-coverage-api-plugin && \
mvn -T${NPROC_VAL} -Dspotbugs.skip=True clean surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "code-coverage-api-plugin"

rmStdout

retval=0
cd ${SRC}/src/jenkins/ && \
mvn -T${NPROC_VAL} -Dtest="ProxyConfigurationTest" -pl test surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "ProxyConfigurationTest"

rmStdout

# build-failure-analyzer-plugin
retval=0
cd ${SRC}/src/plugins/build-failure-analyzer-plugin && \
mvn -T${NPROC_VAL} surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "build-failure-analyzer-plugin"

rmStdout

# email-ext unit tests are too slow, so only EmailConfig and StateRun are tested
retval=0
cd ${SRC}/src/plugins/email-ext-plugin && \
mvn -T${NPROC_VAL} -Dtest=hudson.plugins.emailext.EmailConfigTest,hudson.plugins.emailext.EmailStateRunTest surefire:test | tee ${STDOUT_FILE} || retval=$?
evalRetVal $retval "email-ext-plugin"

rmStdout

if $HAS_FAILURE ; then
  report_test_failure
elif ! $ANY_TESTS_RUN ; then
  die "no tests run?!"
else
  all_good
fi