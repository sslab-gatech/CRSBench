# Local POV re-evaluation of the hybrid random sample

Use `scripts/icse_hybrid_reeval.py` to audit collected attempts and prepare
completed executions while other cloud trials continue. The scientific plan
remains all 135 trial identities in the original 28-benchmark random sample.
A partial collection is not the final study denominator.

## Audit collections

Keep each cloud launch's collection separate. For a live fleet, collect into
a fresh destination; do not overwrite older attempts or tear down the fleet:

```bash
uv run crsbench cloud \
  --config experiment-configs/icse/gce-sample-hybrid-random-remaining-youngjoon-20.yaml \
  collect --dest .run/icse-hybrid/remaining-youngjoon-20-audit-20261114

uv run python scripts/icse_hybrid_reeval.py audit \
  --plan experiment-configs/icse/hybrid-random-batches.json \
  --first .run/icse-hybrid/first \
  --remaining .run/icse-hybrid/remaining .run/icse-hybrid/reduced10-a \
    .run/icse-hybrid/remaining-youngjoon-20-audit-20261114 \
  --output .run/icse-hybrid/collection-audit-20261114.json
```

The audit matches paths and metadata against the frozen plan, checks terminal
markers, required logs and complete-snapshot/archive pairs, and records POV
counts and undrained-verification markers. These are structural checks, not
a byte-level proof of completeness against a deleted remote source. For a
live source, additionally compare remote terminal-trial inventories and file
hashes after collection. Files from still-running trials are moving snapshots
and are not selected for re-evaluation.

Selection requires `.success`, valid metadata, and a recorded positive CRS
run duration. Seed-corpus failures, failed harness evaluations and
operator-excluded partial runs require CRS reruns; POV re-evaluation cannot
repair them. An undrained verification marker does not disqualify a completed
CRS run: its raw POVs are exactly what re-evaluation repairs. Conflicting
markers, damaged completed collections, unexpected identities and multiple
eligible executions of the same identity block preparation. Resolve ambiguous
attempts explicitly; the tool never selects an outcome-preferred duplicate.

## Freeze and run the local sample

```bash
uv run python scripts/icse_hybrid_reeval.py prepare \
  --plan experiment-configs/icse/hybrid-random-batches.json \
  --first .run/icse-hybrid/first \
  --remaining .run/icse-hybrid/remaining .run/icse-hybrid/reduced10-a \
    .run/icse-hybrid/remaining-youngjoon-20-audit-20261114 \
  --sample-size 100 \
  --output .run/icse-hybrid/local-reeval-20261114

bash .run/icse-hybrid/local-reeval-20261114/run-local.sh
```

The default cap is 100 POV files per trial; use `--sample-size 1000` for the
larger historical cap or `0` for all files. Files are ordered by modification
time and filename, divided into equal-count buckets, and one file is selected
from each bucket. The canonical trial key is the random seed, so relocating
the preparation does not change the sample. The manifest records filenames,
SHA-256 hashes and nanosecond modification times. Duplicate content is still
one verification hash and may reduce the number of distinct tested inputs.

Preparation copies metadata, worker logs, accounting files and snapshots into
one isolated experiment tree, along with the selected raw POVs. It preserves
original discovery mtimes and resolves the original trial-start anchor. Old
verification stores, crash logs and undrained markers stay in the raw collection;
the prepared store starts empty. Unsampled original verdicts are not inherited.
This makes results an explicit sampled re-evaluation rather than a mixture of
old and new verification. The old `merge_reeval_into_source.py` overlay is not
used. Trials with a completed CRS run and no POVs remain represented as zero
findings.

The generated script runs the existing `re-eval --local` CLI in place on that
isolated tree, then finalizes the stores and generates CSV reports. It uses
four build jobs and sixteen cores per job by default; override with
`REEVAL_JOBS` and `REEVAL_CORES_PER_JOB`. Local Docker access and the benchmark
ground-truth packages are required. There is no Redis worker or CRS/LLM rerun.
The subset is already fixed, so the script sets
`CRSBENCH_REEVAL_POV_SAMPLE_SIZE=0` to disable a second sampling pass. Ensure
the repository `.env` does not override that variable: the CLI loads dotenv
with override enabled. The completion gate detects an accidental smaller
second sample.

## Completion and aggregation

`verify PREPARED_DIR` is read-only. It requires an unchanged sample inventory,
content and mtimes, the original trial-start anchor, and exactly one usable
verdict for every sampled content hash. Missing verdicts and verification
errors prevent finalization and report generation. Fix build/runtime failures
and rerun the generated script against the same preparation; never replace a
failed verification with an unmatched CPV result.

`finalize PREPARED_DIR` first checks the entire preparation, then rebuilds
per-CPV first-match timestamps from the earliest matching sampled file. This
avoids depending on filename order or verification completion order. Finalizing
again is safe. Original source files are never updated.

Reports are written under
`PREPARED_DIR/reports/<experiment-name>-local-reeval/`. Use `cpv_analysis.csv`
for final per-trial, per-expected-CPV matches. Snapshot-based summary counts
and curves still describe the original online verification and must not be
used as repaired final CPV counts. Trigger times are the earliest observed
matching **sampled** POV times, not necessarily the earliest matching POV in
the full output population. Do not infer exact full-population detection
rates or discovery times from the sampled subset.

`collection-audit.json` retains all planned identities, attempt provenance,
invalid runs and pending keys, even though only eligible completed trials
appear in the prepared analysis tree. Keep it alongside the reports. When
more cloud trials finish, collect separately and prepare a new destination
from all collections. Do not overwrite a prepared or already evaluated sample.
The generated config and runner contain absolute local paths; regenerate the
preparation on another host using its collections and checkout rather than
running an unchanged local runner on a remote worker.
