#!/bin/bash
# [REQUIRED] -e: exit on failure, -x: print executed commands
set -ex

# MVN setting
# [REQUIRED] MUST use $MVN instead of absolute path of mvn. If mvn is not in the path, set the absolute path to $MVN
if [ -z "${MVN}" ]; then
    MVN=mvn
fi

# MVN ARGS setting
## [REQUIRED] Do not modify MVN_SKIP_ARGS as much as possible
MVN_SKIP_ARGS="-Djacoco.skip=true -Dspotless.check.skip=true -Drat.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Dpmd.skip=true -Dlicense.skip=true -Danimal.sniffer.skip=true -Drat.numUnapprovedLicenses=100 -Drat.ignoreErrors=true -Dcheckstyle.skipExec=true -Dspotbugs.skip=true"
## [REQUIRED] You can add additional args needed per project to MVN_ADDITIONAL_ARGS
MVN_ADDITIONAL_ARGS="-Dossindex.skip -Dsurefire.failIfNoSpecifiedTests=false -am -pl :tika-app"
## [REQUIRED] Tests to include. Try to use blacklist as much as possible to maintain high test coverage.
INCLUDE_TESTS=""
if [ -n "$INCLUDE_TESTS" ]; then
    MVN_INCLUDE_TESTS="-Dsurefire.includes=$INCLUDE_TESTS"
fi
## [REQUIRED] Tests to exclude (e.g., failed tests before patching). Minimize this to maintain high test coverage.
EXCLUDE_TESTS="**/TestChmExtraction.java,**/OOXMLParserTest.java,**/TikaIT.java,**/ForkParserTikaBinTest.java,**/ForkParserTest.java,**/ForkParserIntegrationTest.java,**/TikaEncodingDetectorTest.java,**/TikaCLITest.java"
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

# Run Test
## [REQUIRED] Try not to change when using mvn test. Avoid using commands like `clean` as much as possible. Use only if absolutely necessary.
if [ -n "${RTS_ON}" ] && [ "$RTS_TOOL" = "openclover" ]; then
    $MVN clean clover:setup clover:optimize test clover:snapshot $MVN_ARGS -Dmaven.clover.excludesList="**/ForkParser.java,**/ExecutableParser.java,**/XFAExtractor.java"
else
    $MVN test $MVN_ARGS
fi