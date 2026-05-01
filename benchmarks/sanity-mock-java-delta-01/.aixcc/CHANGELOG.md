# Benchmark Changelog

## 2026-05-01 - Artifact anonymization cleanup

Changed files:
- `Dockerfile`
- `pkgs/pkg_refs.txt`
- `pkgs/mock_java.tar.gz`
- `project.yaml`

Root cause:
- The tracked JVM sanity fixture still embedded maintainer-specific Git URLs
  in benchmark metadata and shipped a vendored source tarball with `.git/`
  metadata.

Fix summary:
- Replaced maintainer-specific fixture URLs with an inert
  `https://example.invalid/crsbench-fixtures/...` source marker.
- Replaced the old clone comment in `Dockerfile` with a bundled-fixture note.
- Repacked `pkgs/mock_java.tar.gz` after removing the embedded `.git/`
  directory.

Validation evidence:
- `rg -uu -n '/(home|Users)/' benchmarks/sanity-mock-java-delta-01 --glob '!pkgs/*.tar.gz'`
  -> no matches
- `tar -tzf benchmarks/sanity-mock-java-delta-01/pkgs/mock_java.tar.gz | rg '^.+/.git(/|$)'`
  -> no output

Key diff hunks:

```diff
--- project.yaml
-main_repo: '[maintainer-specific fixture URL removed]'
+main_repo: 'https://example.invalid/crsbench-fixtures/mock-java.git'

--- pkgs/pkg_refs.txt
-[maintainer-specific fixture ref removed]
+https://example.invalid/crsbench-fixtures/mock-java.git@sanitized-fixture

--- Dockerfile
-#RUN git clone [maintainer-specific fixture URL removed] $SRC/src/mock_java
+# Bundled source fixture lives in pkgs/mock_java.tar.gz
```

Binary artifact note:
- `pkgs/mock_java.tar.gz` was repacked after removing the embedded `.git/`
  metadata. The source fixture payload was otherwise left in place.
