# What design decisions were considered for this challenge?
systemd is a large project with many harnesses and a lot of functionailty. The desire was to create a mess of easily fuzzed vulnerabilities that would be challenging for an automated system to deduplicate.

# Why this set of vulnerabilities?
All of these are trivially fuzzable, and it is possible to trigger one of the four vulnerabilities in at least 8 harnesses. Additionally, two of the bugs are double-frees. The goal was to test the CRS's ability to identify the actual root cause of the issue and remidiate it correctly.

# Delta vs Full and why?
Full scan was chosen to force the CRS's to look far and wide for needles in a haystack

# Additional Information

systemd has 50 fuzzing harnesses, 4 of which now have trivially fuzzable bugs. This should help characterize the ability of CRS' ability to handle fuzzzing resources. Hopefully all competitors should be able to generate crashing inputs for all synthetic vulnerabilities. All of the synthetics have some sort of "catch" making them test different axes of the CRS. systemd-001 can be patched in multiple "good" ways that will remediate the bug but there is really only one "correct" answer (that would be approved by a maintainer). systemd-003 tests knowledge of the C preprocessor. systemd-004 will be difficult to deduplicate and is triggerable from at least 4 harnesses. systemd-005 is similar to systemd-001 in that it can be patched in multiple "good" ways that will remediate the single crashing instance of the bug but there is really only one "correct" answer (that will actually fix the root cause of the bug) and is triggerable from at least 2 harnesses.

