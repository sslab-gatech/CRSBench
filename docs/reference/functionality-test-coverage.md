# Functionality-test line coverage

This report records source-line coverage produced by each benchmark's existing
`test.sh` on the reference-patched program. The measurement uses repository
revision `3681ef177df9ad0cce649667265ab3c4252070fe` and was run on
November 17, 2026. The complete per-benchmark results are in
[`functionality-test-coverage.csv`](functionality-test-coverage.csv).

## Scope and metric

The inventory contains 133 `test.sh` scripts: 124 paper benchmarks (63 C/C++,
61 JVM) and 9 sanity benchmarks. The paper-benchmark summary excludes the
sanity cases. Each script was run once per measurement attempt against the
source at its reference commit with all distinct reference patches applied.
The matching OSS-Fuzz builder image supplied the build environment. The
patched source was mounted into that environment before the script ran.

Line coverage is the number of distinct instrumented project source lines
executed during `test.sh` divided by the number of instrumented project source
lines compiled for that test run. It is a percentage of the code built by the
script, not of every source file in the repository. C/C++ runs used Clang
coverage instrumentation and `llvm-cov gcov`; JVM runs used JaCoCo line
counters for production class files. Source paths containing test code or fuzz
harnesses, along with vendored dependencies, were excluded from C/C++
numerators and denominators. JVM test classes were excluded by reporting only
production class directories. The per-benchmark counts in the CSV are the
post-exclusion counts.

A numeric result requires `test.sh` to exit successfully, no reported failure
in its underlying test suite, usable execution data, and at least one
instrumented project source line. A failing test, unavailable dependency,
missing build artifact, or absent execution data is reported without a
coverage percentage. Some scripts suppress a test command's exit code; their
test summaries were checked independently. The libcue script, for example,
ignores `ctest`'s exit code, so its measurement also ran `ctest` separately.

The C/C++ and JVM percentages are comparable as **instrumented line
coverage**, subject to their different build systems and class/source
selection. Repeated benchmarks from the same project remain separate
observations. The measure describes what the available functionality tests
execute; it does not establish regression freedom or include fuzzing coverage.

## Measurement conditions

Coverage jobs for all 133 scripts, plus retries, ran on the local server,
`cerebros`, and `ramjet`.
All three source checkouts were at the revision above. The instrumentation
builds used each benchmark's original test commands; for binutils, an isolated
script copy removed `|| true` so the DejaGnu suite exit status was observable.
The runner preserved script shebang flags and, where necessary, the compiler
environment across `sudo`. JVM projects that fork many test processes used
their Maven or Gradle JaCoCo integration to avoid corrupting one shared
execution-data file. Atlanta Tika's prepared source POM was given a transient
Surefire `@{argLine}` reference so its existing test JVM flags could accept
the Maven JaCoCo agent; production code and the test script were unchanged.
Spring Framework used JaCoCo 0.8.16 for Java 24 class files, excluding test
classes from agent instrumentation. The Mosquitto metadata lists one patch
hunk twice; the second identical application was skipped so the measured
source had the same final content as applying the distinct reference changes
once.

## Results

| Paper benchmark group | Total | Measured | Median line coverage | Mean line coverage |
| --- | ---: | ---: | ---: | ---: |
| C/C++ | 63 | 59 | 60.14% | 45.35% |
| JVM | 61 | 56 | 67.69% | 57.01% |
| All paper benchmarks | 124 | 115 | 62.84% | 51.03% |

These are unweighted summaries across benchmark instances with a valid
measurement; the nine cases without one are excluded from the median and
mean. Measured values range from 0.03% to 92.16%. The per-benchmark line
counts and percentages are in the CSV. Four of the nine sanity benchmarks
also have a numeric result; they are excluded from the paper summary.

## Cases without a passing-suite coverage number

Seven paper benchmarks did not pass their functionality suite under coverage:

| Benchmarks | Observed result |
| --- | --- |
| `atlanta-binutils-delta-01` | DejaGnu reported 37 unexpected failures. The original script masks `make check`'s exit code; the measured retry propagated it. |
| `atlanta-jq-delta-01` | `tests/jqtest` failed once. The original script masks `make check`'s exit code. |
| `atlanta-mongoose-delta-01` | `unit_test` aborted with exit 134 when the script's `-e` shebang was honored. |
| `atlanta-tmux-delta-01` | Four of 19 regression tests failed. |
| `afc-log4j2-delta-01` | `SimplePerfTest` failed timing assertions under coverage instrumentation. |
| `afc-pdfbox-delta-01`, `afc-pdfbox-full-01` | `CreatePDFATest` uses a certificate that expired on June 5, 2026. |

Two more paper benchmarks could not complete their tests because required
dependencies were unavailable: `atlanta-batik-delta-01` could not resolve an
`xmlgraphics-commons` snapshot, and `atlanta-kylin-delta-01` could not resolve
its configured `repository.kyligence.io` host. No passing-suite coverage
percentage is reported for these nine cases.

Among the nine sanity benchmarks, four have measured coverage. The
`sanity-babynote-delta-01`, `sanity-itoa-delta-01`,
`sanity-missing-vulnerabilities-full-01`, and
`sanity-simple-switch-delta-01` scripts only run previously built `/out`
binaries, leaving no instrumented production source to report.
`sanity-mock-java-spam-delta-01` contains no functionality tests.

The CSV's `evidence_host` and `evidence_result` columns identify the selected
raw `result.json` for each row. Local evidence paths are relative to
`.run/functionality-coverage/`; remote paths are relative to
`/home/acorn421/` on the named server. Raw execution logs are in the same
result directories.
