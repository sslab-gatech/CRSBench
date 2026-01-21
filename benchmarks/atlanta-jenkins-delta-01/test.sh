#!/bin/bash
# [REQUIRED] -e: exit on failure, -x: print executed commands
set -ex
source $HOME/.sdkman/bin/sdkman-init.sh

# MVN setting
# [REQUIRED] MUST use $MVN instead of absolute path of mvn. If mvn is not in the path, set the absolute path to $MVN
if [ -z "${MVN}" ]; then
    MVN=mvn
fi

# MVN ARGS setting
## [REQUIRED] Do not modify MVN_SKIP_ARGS as much as possible
MVN_SKIP_ARGS="-Djacoco.skip=true -Dspotless.check.skip=true -Drat.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Dpmd.skip=true -Dlicense.skip=true -Danimal.sniffer.skip=true -Drat.numUnapprovedLicenses=100 -Drat.ignoreErrors=true -Dcheckstyle.skipExec=true -Dspotbugs.skip=true -Dmaven.javadoc.skip=true"
## [REQUIRED] You can add additional args needed per project to MVN_ADDITIONAL_ARGS
MVN_ADDITIONAL_ARGS="-ntp"
## [REQUIRED] Tests to include. Try to use blacklist as much as possible to maintain high test coverage.
INCLUDE_TESTS=""
if [ -n "$INCLUDE_TESTS" ]; then
    MVN_INCLUDE_TESTS="-Dsurefire.includes=$INCLUDE_TESTS"
fi
## [REQUIRED] Tests to exclude (e.g., failed tests before patching). Minimize this to maintain high test coverage.
EXCLUDE_TESTS="**/CauseManagementPermissionTest.java,**/CoverageLeafTest.java,**/CoverageNodeTest.java,**/JobDslITest.java,**/CoverageJobActionTest.java,**/CoverageTest.java,**/CoverageResultTest.java,**/GitForensicsITest.java,**/DeltaComputationVsReferenceBuildITest.java,**/CoverageXmlStreamTest.java,**/CoveragePercentageTest.java,**/CoverageViewModelTest.java"
if [ -n "$EXCLUDE_TESTS" ]; then
    MVN_EXCLUDE_TESTS="-Dsurefire.excludes=$EXCLUDE_TESTS"
fi

## [REQUIRED] MVN_ARGS should not be modified. Add to MVN_ADDITIONAL_ARGS if needed
MVN_ARGS="$MVN_SKIP_ARGS $MVN_ADDITIONAL_ARGS $MVN_INCLUDE_TESTS $MVN_EXCLUDE_TESTS"

# Run RTS configuration if RTS_ON is set
## [REQUIRED] RTS configuration. Do not modify.
if [ -n "${RTS_ON}" ]; then
	echo "[RTS] Running rts_config_jvm.py with tool: ${RTS_TOOL}..."
	python3 /rts_config_jvm.py $(pwd) --tool "${RTS_TOOL}"
else
	echo "[RTS] RTS_ON is not set. Remove cached RTS data..."
	rm -rf .ekstazi || true
fi

# Helper function to run tests with OpenClover support
run_test() {
    local extra_args="${1:-}"
    if [ -n "${RTS_ON}" ] && [ "$RTS_TOOL" = "openclover" ]; then
        $MVN clover:setup clover:optimize test clover:snapshot $MVN_ARGS -Dmaven.clover.skipGroverJar=true -Dsurefire.failIfNoSpecifiedTests=false $extra_args
    else
        $MVN test $MVN_ARGS $extra_args
    fi
}

# Pre-build Jenkins core (required for plugin tests)
cd ${SRC}/src/jenkins && \
$MVN -DskipTests -Denforcer.skip=true -Pquick-build -am -pl bom,war install || exit 1

# Run Tests for each plugin/module
## Note: Jenkins has multiple separate Maven projects (plugins) that need individual test runs

# pipeline-util-plugin
cd ${SRC}/src/plugins/pipeline-util-plugin
run_test

# toy-plugin
cd ${SRC}/src/plugins/toy-plugin
run_test

# code-coverage-api-plugin
CLOVER_TEST_EXCLUDES="**/CoverageLeafTest.java,**/CoverageNodeTest.java,**/JobDslITest.java,**/CoverageJobActionTest.java,**/CoverageTest.java,**/CoverageResultTest.java,**/GitForensicsITest.java,**/DeltaComputationVsReferenceBuildITest.java,**/CoverageXmlStreamTest.java,**/CoveragePercentageTest.java,**/CoverageViewModelTest.java"
cd ${SRC}/src/plugins/code-coverage-api-plugin
run_test "-Dmaven.clover.excludesList=$CLOVER_TEST_EXCLUDES -Dmaven.clover.copyExcludedFiles=false -Dassertj.skip=true"

# ProxyConfigurationTest in jenkins/test
cd ${SRC}/src/jenkins
run_test "-pl test -Dtest=ProxyConfigurationTest"

# build-failure-analyzer-plugin
cd ${SRC}/src/plugins/build-failure-analyzer-plugin
run_test

# email-ext-plugin (only specific tests for performance)
EMAIL_EXT_CLOVER_EXCLUDES="**/ExtendedEmailPublisherContext.java,**/RecipientProviderUtilities.java,**/CulpritsRecipientProvider.java,**/PreviousRecipientProvider.java,**/UpstreamComitterRecipientProvider.java"
cd ${SRC}/src/plugins/email-ext-plugin
run_test "-Dtest=hudson.plugins.emailext.EmailConfigTest,hudson.plugins.emailext.EmailStateRunTest -Dmaven.clover.excludesList=$EMAIL_EXT_CLOVER_EXCLUDES"
