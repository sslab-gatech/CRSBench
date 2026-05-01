# Benchmark Changelog

## 2026-05-01 - Artifact anonymization cleanup

Changed files:
- `Dockerfile`
- `pkgs/pkg_refs.txt`
- `pkgs/mock-c.tar.gz`
- `project.yaml`
- `.aixcc/fuzz_parse_buffer_section/cpv_1/logs/pov_0.log`
- `.aixcc/fuzz_process_input_header/cpv_0/logs/pov_0.log`

Root cause:
- The tracked sanity fixture still embedded maintainer-specific Git URLs,
  local filesystem paths in stored reproduce logs, and a vendored source
  tarball with `.git/` metadata.

Fix summary:
- Replaced maintainer-specific fixture URLs with an inert
  `https://example.invalid/crsbench-fixtures/...` source marker.
- Replaced the old clone comment in `Dockerfile` with a bundled-fixture note.
- Repacked `pkgs/mock-c.tar.gz` after removing the embedded `.git/` directory.
- Redacted local host paths in the checked-in POV reproduce logs to generic
  `/work/oss-fuzz/...` paths.

Validation evidence:
- `rg -uu -n '/(home|Users)/' benchmarks/sanity-mock-c-delta-01 --glob '!pkgs/*.tar.gz'`
  -> no matches
- `tar -tzf benchmarks/sanity-mock-c-delta-01/pkgs/mock-c.tar.gz | rg '^.+/.git(/|$)'`
  -> no output

Key diff hunks:

```diff
--- project.yaml
-main_repo: '[maintainer-specific fixture URL removed]'
+main_repo: 'https://example.invalid/crsbench-fixtures/mock-c.git'

--- pkgs/pkg_refs.txt
-[maintainer-specific fixture ref removed]
+https://example.invalid/crsbench-fixtures/mock-c.git@sanitized-fixture

--- Dockerfile
-#RUN git clone [maintainer-specific fixture URL removed]
+# Bundled source fixture lives in pkgs/mock-c.tar.gz

--- .aixcc/fuzz_process_input_header/cpv_0/logs/pov_0.log
-INFO:__main__:Running: docker run ... -v [local path redacted]:/out -v [local path redacted]:/testcase ...
+INFO:__main__:Running: docker run ... -v /work/oss-fuzz/build/out/mock-c:/out -v /work/oss-fuzz/projects/mock-c/.aixcc/povs/fuzz_process_input_header/cpv_0:/testcase ...

--- .aixcc/fuzz_parse_buffer_section/cpv_1/logs/pov_0.log
-INFO:__main__:Running: docker run ... -v [local path redacted]:/out -v [local path redacted]:/testcase ...
+INFO:__main__:Running: docker run ... -v /work/oss-fuzz/build/out/mock-c:/out -v /work/oss-fuzz/projects/mock-c/.aixcc/povs/fuzz_parse_buffer_section/cpv_1:/testcase ...
```

Binary artifact note:
- `pkgs/mock-c.tar.gz` was repacked after removing the embedded `.git/`
  metadata. The source fixture payload was otherwise left in place.
