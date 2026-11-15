# Local POV re-evaluation of the hybrid random sample

Use `scripts/icse_hybrid_reeval.py` to audit collected attempts and prepare
completed executions while other cloud trials continue. The scientific plan
remains all 135 trial identities in the original 28-benchmark random sample.
A partial collection is not the final study denominator.

## Audit collections

Keep each cloud launch's collection separate. For a live fleet, collect into
a fresh destination; do not overwrite older attempts or tear down the fleet.
When collecting the same live launch again, keep both raw snapshots but pass
only its newest verified snapshot to the audit. First confirm it still contains
every previously collected completed identity and its raw POV files. Passing
two snapshots containing the same completed execution intentionally blocks as
a duplicate; it does not represent an additional scientific trial.

For the current launch:

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
  --sample-size 500 \
  --output .run/icse-hybrid/local-reeval-500-20261114

bash .run/icse-hybrid/local-reeval-500-20261114/run-local.sh
```

The study cap and default are 500 POV files per trial. The preparation tool
accepts only caps from 1 through 500; uncapped and larger samples are rejected.
The earlier 100-file preparation is retained as a separate historical artifact.
Files are ordered by modification
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
findings. A zero-POV execution must have an existing empty `output/povs`
directory; a missing directory is collection damage, not evidence of zero POVs.
An empty directory that contradicts a nonempty original POV store also blocks
preparation.

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
using the first, original remaining and reduced-A collections plus the newest
verified snapshot of the current launch. Replace the older snapshot argument
for that same launch; do not pass both snapshots. If the newest snapshot no
longer contains earlier completed results, retain those earlier identities in
an explicitly audited staging collection before preparing. Do not overwrite
a prepared or already evaluated sample.
The generated config and runner contain absolute local paths; regenerate the
preparation on another host using its collections and checkout rather than
running an unchanged local runner on a remote worker.
The generated config sets `verify_timeout` to 48 hours. Distributed re-eval
drains all sampled POVs in one batch; the engine's default two-hour deadline
can expire while healthy evaluators still have a large backlog. This deadline
still bounds stalled runs, and individual POVs retain their 300-second limit.

## Other servers and the existing remote re-evaluation paths

Re-evaluation is not tied to cyclonus. An ordinary SSH server can run the
same `crsbench re-eval --local` command when it has the matching CRSBench
checkout, pinned OSS-Fuzz helpers, Docker access and benchmark ground-truth
packages. Transfer collection inputs with `rsync -a` to preserve discovery
mtimes, transfer the frozen trial plan, and run `prepare` in that server's
checkout. This regenerates the absolute config/runner paths for that host.
Keep the 500-file cap, timeout and source/build policy the same. A successful
SSH or Docker probe alone does not establish that the runtime and ground
truth match; verify those before starting paper-data verification.

Two existing distributed entry points are also available:

- `crsbench re-eval -c CONFIG --redis-host HOST:6379` submits verification
  through the configured distributed queues to evaluator processes. This
  requires a working evaluator runtime and its build prerequisites, not just
  remote CRS workers.
- `crsbench cloud --config CONFIG re-eval --from EXPERIMENT_TREE
  --remote-experiment NAME` packages inputs and provisions a GCE orchestrator
  and evaluator fleet, without CRS worker VMs. `CONFIG` must contain cloud
  configuration; the minimal local `reeval.yaml` is not a cloud launch config.
  Collection uses the existing cloud collection workflow. Do not use the
  active finding experiment's identity/state for a new re-evaluation fleet.

The cloud implementation is in `crsbench/cloud/reeval_bundle.py`,
`crsbench/cloud/reeval_remote.py`, and `crsbench/cloud/cli/_reeval.py`. It was
introduced by `a61ad3b3` (`feat(cloud): add distributed cloud re-eval flow`).
The old `scripts/orchestrate-workers.sh` targets historical machine/user/path
layouts and CRS workers; it is not a portable re-evaluation launcher.

There are two study-specific requirements before using distributed execution:

- Set `CRSBENCH_REEVAL_POV_SAMPLE_SIZE=0` in the remote coordinator's effective
  environment, including any dotenv override. The input is already capped at
  500; a remote default of 100 would silently reduce it again. Check the
  returned hashes against the frozen sample manifest before accepting results.
- The existing cloud bundle selects only trials with nonempty re-evaluation
  inputs. In the current 80-trial collection it selects 76 trials and skips
  the four genuine zero-POV executions. Keep those four in the unified
  analysis tree and audit; do not compute the paper denominator from the
  remote bundle's selected-trial count. Bring verified stores back to their
  matching relative paths in that tree, then use `finalize` and the local
  reporting workflow. Unreturned/error verdicts remain unresolved.

Remote runtime compatibility requires the same committed revision. Ground-truth
package identity must also be checked; matching benchmark names alone does
not prove that their data is identical. Server readiness probes and bundle
checks are inspection only and do not launch verification or provision VMs.
