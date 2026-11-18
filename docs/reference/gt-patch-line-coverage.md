# GT patch changed-line coverage in functionality tests

This report checks whether the existing functionality tests execute source
lines added or modified by the ground-truth (GT) patches. It extends the
[functionality-test coverage report](functionality-test-coverage.md), whose
percentages describe all instrumented project code rather than patch-specific
execution. The benchmark-by-benchmark results are in
[`gt-patch-line-coverage.csv`](gt-patch-line-coverage.csv); final patch line
numbers and each line's observed state are in
[`gt-patch-line-coverage-evidence.jsonl`](gt-patch-line-coverage-evidence.jsonl).

## How the measurements were made

The original coverage measurement applied each benchmark's distinct GT
patches to its reference source, instrumented the build, and ran its existing
`test.sh`. C/C++ used Clang `--coverage` and `llvm-cov gcov`; JVM used JaCoCo.
It divided executed instrumented production lines by all instrumented
production lines built for that run. Seven failing full suites also have
separate measurements of their passing test subsets. The original report
records the exact test selection, exclusions, and source scope.

For this analysis, the reference source before patching was compared with
the source after **all** GT patches were applied. A zero-context final diff
provided the actual post-patch line numbers of additions and modifications.
This matters when multiple patches move the same file's line numbers. Five
benchmarks have deletion-only patches and therefore have no added or modified
line to score. The full map includes 58,005 added or modified lines across 124
paper benchmarks; many are tests, documentation, JSP, or other files outside
the production C/C++ and Java line-coverage instruments.

Each final changed production source line was matched to its coverage record:
`llvm-cov gcov` line count greater than zero means executed for C/C++, and a
JaCoCo XML line with `ci > 0` means executed for JVM. An instrumented line
with zero execution is **missed**. A source file reported without that line is
**not instrumented**; a source file with no matching coverage record is
**source not reported**. Neither category is counted as a zero-execution
instrumented line. Test sources, fuzz harnesses, and non-C/C++ or non-Java
files are shown separately from the production-source calculation.

Line-level records were available from the selected JVM coverage runs for
56 benchmarks and from the selected C/C++ runs for nine. The other 54 C/C++
benchmarks were rerun with line-level gcov output retained. Their instrumented
line denominators exactly match the original selected runs; individual hit
counts can differ slightly between test executions. Three JVM reports
(Feign, Jenkins, Keycloak) stored only aggregate counters, so the same
reference-patched source and functionality tests were rerun to retain module
JaCoCo XML. Their per-line verdicts are explicitly marked as verification
reruns in the CSV and evidence. Where a full test suite had failed, the
passing-subset selection from the original report was reused.

## Results

| Paper benchmarks | At least one GT source line executed | Instrumented GT lines, none executed | No instrumented changed source line | Deletion-only patch | Test dependency unavailable |
| --- | ---: | ---: | ---: | ---: | ---: |
| C/C++ (63) | 35 | 19 | 6 | 3 | 0 |
| JVM (61) | 43 | 9 | 5 | 2 | 2 |
| **All (124)** | **78** | **28** | **11** | **5** | **2** |

Among the 106 benchmarks with at least one instrumented GT-changed source
line, 78 executed at least one such line and 28 executed none.

Across the 122 benchmarks with a functionality-test coverage result, 3,164
GT-changed production source lines appear in the line-coverage denominator.
Of these, **2,115 were executed and 1,049 were missed**: 66.85% of the
instrumented changed lines executed. The C/C++ count is 214/521 (41.07%);
the JVM count is 1,901/2,643 (71.93%). These line-weighted percentages are
strongly affected by large patches, so the benchmark counts above are the
primary summary. Another 12,132 changed production source lines were not
instrumented, and 677 were in source files with no matching line-coverage
record; they are not in the 3,164-line denominator. The two dependency-blocked
benchmarks have no GT line execution verdict.

The distinction from overall project coverage is concrete. Log4j2's patched
`JndiLookup.java:31` ran in its passing subset (1/1 instrumented GT line).
Keycloak had approximately 12% overall project line coverage, but all 49
instrumented lines changed by its GT patch were missed. All eight Wireshark
benchmarks had approximately 9% overall coverage: seven had instrumented GT
lines but executed none, while the eighth had no instrumented GT line. The CSV
contains the corresponding counts for every benchmark.

Executing a changed line shows reachability during the tests; it does not
prove that an assertion checked the intended security behavior. Conversely,
a deletion-only patch has no added line whose execution can be measured by
this method. Source files absent from a gcov or JaCoCo report may be unbuilt,
outside the instrumented target, or represented through a generated copy;
absence alone is not evidence that the behavior was never tested.

## Evidence

The committed evidence JSONL contains one record for each of the 124 paper
benchmarks: applied GT patch paths, reference commit, final changed file/line
numbers, and the per-line coverage verdict. The C/C++ records point to
compressed `line_coverage.json.gz` files; JVM records point to JaCoCo XML or
the saved module XMLs from verification reruns. These raw files and test logs
remain in the local or remote `.run/functionality-coverage/` result directories
identified in the evidence. The two dependency-blocked cases retain their GT
patch maps but have no line-coverage record.
