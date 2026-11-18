# Functionality-test line coverage

This report records source-line coverage produced by each benchmark's existing
`test.sh` on the reference-patched program. The measurement uses repository
revision `3681ef177df9ad0cce649667265ab3c4252070fe` and was run on
November 17, 2026. The complete per-benchmark results are in
[`functionality-test-coverage.csv`](functionality-test-coverage.csv).
For coverage of the lines changed by GT patches specifically, see the
[GT patch changed-line report](gt-patch-line-coverage.md).

## Scope and metric

The inventory contains 133 `test.sh` scripts: 124 paper benchmarks (63 C/C++,
61 JVM) and 9 sanity benchmarks. The paper-benchmark summary excludes the
sanity cases. Each script was run once per measurement attempt against the
source at its reference commit with all distinct reference patches applied.
The matching OSS-Fuzz builder image supplied the build environment. The
patched source was mounted into that environment before the script ran.

Line coverage is the number of distinct instrumented project source lines
executed during `test.sh` divided by the number of instrumented project source
lines compiled for that measurement. It is a percentage of the code built for
the test run, not of every source file in the repository. C/C++ runs used Clang
coverage instrumentation and `llvm-cov gcov`; JVM runs used JaCoCo line
counters for production class files. Source paths containing test code or fuzz
harnesses, examples, and benchmark programs, along with vendored dependencies,
were excluded from C/C++ numerators and denominators. Project-owned features
such as SQLite's `ext/misc/fuzzer.c` remain included. The exact C/C++ source
exclusions and their line counts are recorded in each evidence record's
`line_scope` field. Source files compiled through multiple paths were merged
by source line number; the affected records also list those duplicate groups.
JVM test classes were excluded by reporting only production
class directories. The per-benchmark counts in the CSV are the post-exclusion
counts.

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
NASM and libcue needed their benchmark build step before `test.sh`; their
denominators include code built in that preparatory step.
Spring Framework used JaCoCo 0.8.16 for Java 24 class files, excluding test
classes from agent instrumentation. The Mosquitto metadata lists one patch
hunk twice; the second identical application was skipped so the measured
source had the same final content as applying the distinct reference changes
once.
The Atlanta Wireshark line-level verification rerun used `make -j16` in a
temporary script copy to shorten its build; it ran the same tests against the
same reference-patched source.

## Results

| Paper benchmark group | Total | Measured | Median line coverage | Mean line coverage |
| --- | ---: | ---: | ---: | ---: |
| C/C++ | 63 | 59 | 60.14% | 45.93% |
| JVM | 61 | 56 | 67.69% | 57.01% |
| All paper benchmarks | 124 | 115 | 63.28% | 51.32% |

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
its configured `repository.kyligence.io` host. No full-suite passing coverage
percentage is reported for these nine cases; seven have passing-subset values
below.

## Coverage from passing subsets

The seven paper benchmarks whose full suites failed were rerun with the
observed failing tests excluded. These are separate measurements of the
remaining passing tests. The original full-suite `test_failed` status remains
in the CSV; its `passing_subset_*` columns hold the results below. Test
selection was changed only in temporary measurement copies; production source
and tracked benchmark files were not changed.

| Benchmark | Excluded from rerun | Passing subset | Covered / instrumented lines | Line coverage |
| --- | --- | ---: | ---: | ---: |
| `atlanta-binutils-delta-01` | 37 failing DejaGnu cases | 283 PASS | 26,923 / 453,648 | 5.93% |
| `atlanta-jq-delta-01` | `tests/jqtest` | 27 PASS | 5,984 / 12,270 | 48.77% |
| `atlanta-mongoose-delta-01` | `test_mqtt()` and `test_http_client()` | 1,109 assertions PASS | 2,864 / 3,385 | 84.61% |
| `atlanta-tmux-delta-01` | Four failing regression scripts | 15 PASS | 12,559 / 37,908 | 33.13% |
| `afc-log4j2-delta-01` | `SimplePerfTest` (three failing methods) | 705 PASS, 4 SKIP | 9,708 / 15,016 | 64.65% |
| `afc-pdfbox-delta-01` | `CreatePDFATest.testCreatePDFA` | 1,796 PASS, 12 SKIP | 35,860 / 63,061 | 56.87% |
| `afc-pdfbox-full-01` | `CreatePDFATest.testCreatePDFA` | 1,788 PASS, 12 SKIP | 35,798 / 62,969 | 56.85% |

The three excluded JVM test classes contain only the originally failing
active test methods; no other passing JVM tests were removed. The JVM reruns
used the same reference-patched production source, a host Java truststore for
PDFBox's HTTPS downloads, and a Maven Central mirror after the default
repository returned HTTP 429. DejaGnu has no
per-assertion exclusion switch, so the binutils selection also omits three
passing cases in the same test calls: the original run had 286 expected passes
and the subset has 283. The Mongoose selection omits two whole network
dependent test functions. These scope differences make the subset percentages
distinct from the full-suite numbers summarized above. With these seven
additional subset measurements, **122 of 124** paper benchmarks have a
reported coverage percentage; the two dependency failures still have none.

Among the nine sanity benchmarks, four have measured coverage. The
`sanity-babynote-delta-01`, `sanity-itoa-delta-01`,
`sanity-missing-vulnerabilities-full-01`, and
`sanity-simple-switch-delta-01` scripts only run previously built `/out`
binaries, leaving no instrumented production source to report.
`sanity-mock-java-spam-delta-01` contains no functionality tests.

The committed
[`functionality-test-coverage-evidence.jsonl`](functionality-test-coverage-evidence.jsonl)
contains one record per benchmark with the selected raw result, including
C/C++ file-level counts, and relevant test-log excerpts for unavailable
results and masked test commands. For the seven reruns above, each evidence
record also contains the passing-subset result, exclusions, test summary, and
selection script or method-scope evidence. C/C++ records additionally list
the source files excluded from each coverage calculation in `line_scope`.
The CSV's `evidence_host` and
`evidence_result` columns identify the full run directory: local paths are
relative to `.run/functionality-coverage/`, and remote paths are relative to
`/home/acorn421/` on the named server. Full execution logs remain in those
directories.
